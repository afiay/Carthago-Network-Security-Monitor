// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED — 0 EXECUTED.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;

namespace Carthago.Services.SessionFiles;

/// <summary>
/// One or more sheets per category. JSON numbers and booleans are exported as
/// native Excel values; strings always remain literal text, never formulas.
/// An Excel-only DataQuality sheet explains null/unknown/redacted coverage.
/// </summary>
public sealed class CarthagoExcelExportService
{
    internal const int MaximumDataRowsPerSheet = 1_048_575; // Excel's 1,048,576 includes the header.
    private const int MaximumTextLength = 32767;
    internal const string DataQualitySheetName = "DataQuality";

    private readonly record struct ExcelCellValue(CellValues DataType, string Value)
    {
        internal static ExcelCellValue Text(string value) => new(CellValues.InlineString, value);
    }

    private enum DataValueState
    {
        Populated,
        NullOrAbsent,
        UnknownSentinel,
        Redacted
    }

    public Task ExportAsync(string destination, CarthagoSessionSnapshot snapshot, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        if (!string.Equals(Path.GetExtension(destination), ".xlsx", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Excel export requires an .xlsx destination.");
        return Task.Run(() => ExportCore(destination, snapshot, token), token);
    }

    private static void ExportCore(string destination, CarthagoSessionSnapshot snapshot, CancellationToken token)
    {
        string fullPath = Path.GetFullPath(destination);
        string tempPath = fullPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var file = new FileStream(tempPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
            using (var spreadsheet = SpreadsheetDocument.Create(file, SpreadsheetDocumentType.Workbook))
            {
                WorkbookPart workbookPart = spreadsheet.AddWorkbookPart();
                workbookPart.Workbook = new Workbook();
                Sheets sheets = workbookPart.Workbook.AppendChild(new Sheets());
                uint sheetId = 1;

                foreach (string category in CarthagoSessionSnapshot.CategoryOrder)
                {
                    token.ThrowIfCancellationRequested();
                    snapshot.Categories.TryGetValue(category, out List<JsonElement>? items);
                    AppendWorksheetPages(
                        workbookPart,
                        sheets,
                        category,
                        items ?? new List<JsonElement>(),
                        ref sheetId,
                        token);
                }

                AppendWorksheetPages(
                    workbookPart,
                    sheets,
                    DataQualitySheetName,
                    BuildDataQualityRows(snapshot),
                    ref sheetId,
                    token);

                workbookPart.Workbook.Save();
            }
            File.Move(tempPath, fullPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(tempPath)) File.Delete(tempPath);
        }
    }

    private static void AppendWorksheetPages(
        WorkbookPart workbookPart,
        Sheets sheets,
        string category,
        IReadOnlyList<JsonElement> items,
        ref uint sheetId,
        CancellationToken token)
    {
        var columns = items.SelectMany(GetColumnNames).Distinct(StringComparer.Ordinal).ToList();
        if (columns.Count == 0) columns.Add("Status");
        if (columns.Count > 16_384) throw new InvalidOperationException("Excel column limit exceeded.");

        int numberOfSheets = Math.Max(1,
            (int)Math.Ceiling(items.Count / (double)MaximumDataRowsPerSheet));

        for (int page = 0; page < numberOfSheets; page++)
        {
            token.ThrowIfCancellationRequested();
            int first = checked(page * MaximumDataRowsPerSheet);
            int end = Math.Min(items.Count, first + MaximumDataRowsPerSheet);
            uint dataRowCount = checked((uint)(end - first));
            string lastColumn = GetColumnName(columns.Count);
            string usedRange = $"A1:{lastColumn}{dataRowCount + 1}";

            WorksheetPart worksheet = workbookPart.AddNewPart<WorksheetPart>();
            using (var writer = OpenXmlWriter.Create(worksheet))
            {
                writer.WriteStartElement(new Worksheet());
                writer.WriteElement(new SheetDimension { Reference = usedRange });

                writer.WriteStartElement(new SheetViews());
                var view = new SheetView { WorkbookViewId = 0U };
                view.Append(new Pane
                {
                    VerticalSplit = 1D,
                    TopLeftCell = "A2",
                    ActivePane = PaneValues.BottomLeft,
                    State = PaneStateValues.Frozen
                });
                writer.WriteElement(view);
                writer.WriteEndElement(); // SheetViews

                writer.WriteStartElement(new SheetData());
                WriteRow(writer, columns.Select(ExcelCellValue.Text), 1U);
                uint excelRow = 2U;
                for (int row = first; row < end; row++, excelRow++)
                {
                    token.ThrowIfCancellationRequested();
                    JsonElement item = items[row];
                    WriteRow(writer, columns.Select(c => GetExcelCellValue(item, c)), excelRow);
                }
                writer.WriteEndElement(); // SheetData

                if (dataRowCount > 0)
                    writer.WriteElement(new AutoFilter { Reference = usedRange });

                writer.WriteEndElement(); // Worksheet
            }

            string sheetName = numberOfSheets == 1 ? category : $"{category} {page + 1}";
            sheets.Append(new Sheet
            {
                Name = sheetName,
                SheetId = sheetId++,
                Id = workbookPart.GetIdOfPart(worksheet)
            });
        }
    }

    internal static IReadOnlyList<JsonElement> BuildDataQualityRows(CarthagoSessionSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var output = new List<JsonElement>();

        foreach (string category in CarthagoSessionSnapshot.CategoryOrder)
        {
            if (!snapshot.Categories.TryGetValue(category, out List<JsonElement>? items)
                || items.Count == 0)
                continue;

            string[] columns = items
                .SelectMany(GetColumnNames)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(name => name, StringComparer.Ordinal)
                .ToArray();

            foreach (string column in columns)
            {
                int populated = 0;
                int missing = 0;
                int unknown = 0;
                int redacted = 0;

                foreach (JsonElement item in items)
                {
                    switch (Classify(item, column))
                    {
                        case DataValueState.Populated:
                            populated++;
                            break;
                        case DataValueState.NullOrAbsent:
                            missing++;
                            break;
                        case DataValueState.UnknownSentinel:
                            unknown++;
                            break;
                        case DataValueState.Redacted:
                            redacted++;
                            break;
                    }
                }

                output.Add(JsonSerializer.SerializeToElement(new
                {
                    Category = category,
                    Field = column,
                    Rows = items.Count,
                    PopulatedValues = populated,
                    NullOrAbsentValues = missing,
                    UnknownSentinelValues = unknown,
                    RedactedValues = redacted,
                    UsableCoveragePercent = Math.Round(populated * 100.0 / items.Count, 1),
                    Interpretation = MissingValueInterpretation(category, column)
                }, SessionJson.Options));
            }
        }

        return output;
    }

    private static DataValueState Classify(JsonElement item, string column)
    {
        if (item.ValueKind != JsonValueKind.Object
            || !item.TryGetProperty(column, out JsonElement value))
            return DataValueState.NullOrAbsent;

        if (value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
            return DataValueState.NullOrAbsent;

        if (value.ValueKind == JsonValueKind.String)
        {
            string? text = value.GetString();
            if (string.IsNullOrWhiteSpace(text))
                return DataValueState.NullOrAbsent;
            if (string.Equals(text, "[REDACTED]", StringComparison.Ordinal))
                return DataValueState.Redacted;
            if (IsUnknownSentinel(column, text))
                return DataValueState.UnknownSentinel;
            return DataValueState.Populated;
        }

        if (value.ValueKind == JsonValueKind.Array && value.GetArrayLength() == 0)
            return DataValueState.NullOrAbsent;
        if (value.ValueKind == JsonValueKind.Object && !value.EnumerateObject().Any())
            return DataValueState.NullOrAbsent;

        if (string.Equals(column, "ProcessId", StringComparison.OrdinalIgnoreCase)
            && value.ValueKind == JsonValueKind.Number
            && value.TryGetInt64(out long processId)
            && processId <= 0)
            return DataValueState.UnknownSentinel;

        return DataValueState.Populated;
    }

    private static bool IsUnknownSentinel(string column, string value)
    {
        if (string.Equals(value, "Unknown", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "Unavailable", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "Unresolved", StringComparison.OrdinalIgnoreCase))
            return true;

        return string.Equals(value, "N/A", StringComparison.OrdinalIgnoreCase)
            && (column.Contains("Checksum", StringComparison.OrdinalIgnoreCase)
                || column.Contains("Process", StringComparison.OrdinalIgnoreCase)
                || column.Contains("NetworkType", StringComparison.OrdinalIgnoreCase));
    }

    private static string MissingValueInterpretation(string category, string field)
    {
        if (field.StartsWith("Http", StringComparison.OrdinalIgnoreCase)
            || field.StartsWith("Tls", StringComparison.OrdinalIgnoreCase)
            || field.StartsWith("Ja", StringComparison.OrdinalIgnoreCase)
            || field.StartsWith("Dns", StringComparison.OrdinalIgnoreCase)
            || field.StartsWith("Quic", StringComparison.OrdinalIgnoreCase)
            || field.StartsWith("Mqtt", StringComparison.OrdinalIgnoreCase)
            || field.StartsWith("Redis", StringComparison.OrdinalIgnoreCase)
            || field.StartsWith("Ldap", StringComparison.OrdinalIgnoreCase)
            || field.StartsWith("Bacnet", StringComparison.OrdinalIgnoreCase)
            || field.StartsWith("Tcp", StringComparison.OrdinalIgnoreCase)
            || field.StartsWith("Icmp", StringComparison.OrdinalIgnoreCase)
            || field.StartsWith("IpFragment", StringComparison.OrdinalIgnoreCase))
            return "Protocol/evidence-specific field: blank is expected when that protocol, parser or observation does not apply to the row.";

        if (field.StartsWith("Whois", StringComparison.OrdinalIgnoreCase)
            || field.StartsWith("Reputation", StringComparison.OrdinalIgnoreCase)
            || field.StartsWith("SrcCountry", StringComparison.OrdinalIgnoreCase)
            || field.StartsWith("DstCountry", StringComparison.OrdinalIgnoreCase)
            || field.StartsWith("SrcAsn", StringComparison.OrdinalIgnoreCase)
            || field.StartsWith("DstAsn", StringComparison.OrdinalIgnoreCase)
            || string.Equals(field, "SrcCity", StringComparison.OrdinalIgnoreCase)
            || string.Equals(field, "DstCity", StringComparison.OrdinalIgnoreCase)
            || field.EndsWith("Lat", StringComparison.OrdinalIgnoreCase)
            || field.EndsWith("Lon", StringComparison.OrdinalIgnoreCase))
            return "Enrichment field: blank means the enrichment source did not provide a value for this snapshot; it is not inferred.";

        if (field.StartsWith("Process", StringComparison.OrdinalIgnoreCase))
            return "Local process attribution: blank/Unknown or ProcessId 0 means attribution was unavailable, not that a process identity was confirmed.";

        if (string.Equals(category, "Rules", StringComparison.OrdinalIgnoreCase))
            return "Rule metadata: blank means that descriptor/intelligence/precision metadata does not define this optional value.";

        return "Blank means the source record supplied null, empty or no value. [REDACTED] is tracked separately and means intentionally removed.";
    }

    internal static IEnumerable<string> GetColumnNames(JsonElement item)
        => item.ValueKind == JsonValueKind.Object
            ? item.EnumerateObject().Select(p => p.Name)
            : new[] { "Value" };

    internal static string GetCellValue(JsonElement item, string column)
    {
        if (item.ValueKind == JsonValueKind.Object)
        {
            if (!item.TryGetProperty(column, out JsonElement value)) return string.Empty;
            return RenderJsonValue(value);
        }
        return column == "Value" ? RenderJsonValue(item) : string.Empty;
    }

    private static ExcelCellValue GetExcelCellValue(JsonElement item, string column)
    {
        if (item.ValueKind == JsonValueKind.Object)
        {
            if (!item.TryGetProperty(column, out JsonElement value))
                return ExcelCellValue.Text(string.Empty);
            return ToExcelCellValue(value);
        }

        return column == "Value"
            ? ToExcelCellValue(item)
            : ExcelCellValue.Text(string.Empty);
    }

    private static ExcelCellValue ToExcelCellValue(JsonElement value)
        => value.ValueKind switch
        {
            JsonValueKind.Number => new ExcelCellValue(CellValues.Number, value.GetRawText()),
            JsonValueKind.True => new ExcelCellValue(CellValues.Boolean, "1"),
            JsonValueKind.False => new ExcelCellValue(CellValues.Boolean, "0"),
            _ => ExcelCellValue.Text(RenderJsonValue(value))
        };

    private static string RenderJsonValue(JsonElement value)
    {
        string result = value.ValueKind switch
        {
            JsonValueKind.Null or JsonValueKind.Undefined => "",
            JsonValueKind.String => value.GetString() ?? "",
            _ => value.GetRawText()
        };
        // String/array/object cells remain InlineString, so formula-like content
        // can never become executable spreadsheet formulas.
        return result.Length <= MaximumTextLength
            ? result
            : result[..(MaximumTextLength - 18)] + " [TRUNCATED]";
    }

    private static void WriteRow(OpenXmlWriter writer, IEnumerable<ExcelCellValue> values, uint rowIndex)
    {
        writer.WriteStartElement(new Row { RowIndex = rowIndex });
        int columnIndex = 1;
        foreach (ExcelCellValue value in values)
        {
            var cell = new Cell
            {
                CellReference = GetColumnName(columnIndex++) + rowIndex,
                DataType = value.DataType
            };

            if (value.DataType == CellValues.InlineString)
            {
                cell.InlineString = new InlineString(
                    new Text(value.Value) { Space = SpaceProcessingModeValues.Preserve });
            }
            else
            {
                cell.CellValue = new CellValue(value.Value);
            }

            writer.WriteElement(cell);
        }
        writer.WriteEndElement();
    }

    private static string GetColumnName(int oneBasedColumnIndex)
    {
        if (oneBasedColumnIndex <= 0)
            throw new ArgumentOutOfRangeException(nameof(oneBasedColumnIndex));

        string name = string.Empty;
        int value = oneBasedColumnIndex;
        while (value > 0)
        {
            value--;
            name = (char)('A' + value % 26) + name;
            value /= 26;
        }
        return name;
    }
}
