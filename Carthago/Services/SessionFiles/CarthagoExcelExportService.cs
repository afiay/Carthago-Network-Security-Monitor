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
/// </summary>
public sealed class CarthagoExcelExportService
{
    internal const int MaximumDataRowsPerSheet = 1_048_575; // Excel's 1,048,576 includes the header.
    private const int MaximumTextLength = 32767;

    private readonly record struct ExcelCellValue(CellValues DataType, string Value)
    {
        internal static ExcelCellValue Text(string value) => new(CellValues.InlineString, value);
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
                    items ??= new List<JsonElement>();
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
                workbookPart.Workbook.Save();
            }
            File.Move(tempPath, fullPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(tempPath)) File.Delete(tempPath);
        }
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
