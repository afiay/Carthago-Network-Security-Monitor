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

/// <summary>One or more sheets per category; no formula cells or external links.</summary>
public sealed class CarthagoExcelExportService
{
    internal const int MaximumDataRowsPerSheet = 1_048_575; // Excel's 1,048,576 includes the header.
    private const int MaximumTextLength = 32767;

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
                    int numberOfSheets = Math.Max(1, (int)Math.Ceiling(items.Count / (double)MaximumDataRowsPerSheet));
                    for (int page = 0; page < numberOfSheets; page++)
                    {
                        token.ThrowIfCancellationRequested();
                        WorksheetPart worksheet = workbookPart.AddNewPart<WorksheetPart>();
                        using (var writer = OpenXmlWriter.Create(worksheet))
                        {
                            writer.WriteStartElement(new Worksheet());
                            writer.WriteStartElement(new SheetData());
                            WriteRow(writer, columns);
                            int first = checked(page * MaximumDataRowsPerSheet);
                            int end = Math.Min(items.Count, first + MaximumDataRowsPerSheet);
                            for (int row = first; row < end; row++)
                            {
                                token.ThrowIfCancellationRequested();
                                JsonElement item = items[row];
                                WriteRow(writer, columns.Select(c => GetCellValue(item, c)));
                            }
                            writer.WriteEndElement(); // SheetData
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

    private static string RenderJsonValue(JsonElement value)
    {
        string result = value.ValueKind switch
        {
            JsonValueKind.Null or JsonValueKind.Undefined => "",
            JsonValueKind.String => value.GetString() ?? "",
            _ => value.GetRawText()
        };
        // Open XML InlineString is always text: it cannot execute spreadsheet formulas.
        return result.Length <= MaximumTextLength ? result : result[..(MaximumTextLength - 18)] + " [TRUNCATED]";
    }

    private static void WriteRow(OpenXmlWriter writer, IEnumerable<string> values)
    {
        writer.WriteStartElement(new Row());
        foreach (string value in values)
        {
            writer.WriteElement(new Cell
            {
                DataType = CellValues.InlineString,
                InlineString = new InlineString(new Text(value) { Space = SpaceProcessingModeValues.Preserve })
            });
        }
        writer.WriteEndElement();
    }
}
