// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED — 0 EXECUTED.
using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Services.SessionFiles;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;
using Xunit;

namespace Carthago.Tests;

public sealed class CarthagoSessionFileTests
{
    [Fact]
    public async Task CsaRoundtripPreservesEveryCategoryAndRedactsMarkedEvidence()
    {
        string directory = NewTestDirectory();
        try
        {
            string path = Path.Combine(directory, "review.csa");
            var original = CarthagoSessionSnapshot.CreateEmpty();
            original.Limitations.Add("Recent traffic only");
            original.AddRows("Traffic", new[] { new { Source = "192.0.2.7", Protocol = "DNS" } });
            original.AddRows("Evidence", new[]
            {
                new { RuleId = "R102", IsSensitive = true, Value = "secret-value" }
            });

            var archive = new CarthagoSessionArchiveService();
            await archive.SaveAsync(path, original);
            var loaded = await archive.OpenAsync(path);

            Assert.Equal(CarthagoSessionSnapshot.CategoryOrder.Length, loaded.Categories.Count);
            Assert.Single(loaded.Categories["Traffic"]);
            Assert.Equal("DNS", loaded.Categories["Traffic"][0].GetProperty("Protocol").GetString());
            Assert.Equal("[REDACTED]", loaded.Categories["Evidence"][0].GetProperty("Value").GetString());
            Assert.Contains("Recent traffic only", loaded.Limitations);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public async Task CsaRejectsEntryTampering()
    {
        string directory = NewTestDirectory();
        try
        {
            string path = Path.Combine(directory, "integrity.csa");
            var archive = new CarthagoSessionArchiveService();
            var original = CarthagoSessionSnapshot.CreateEmpty();
            original.AddRows("Traffic", new[] { new { Source = "192.0.2.7" } });
            await archive.SaveAsync(path, original);

            using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
            {
                zip.GetEntry("data/Traffic.json")!.Delete();
                using var entryStream = zip.CreateEntry("data/Traffic.json").Open();
                byte[] modified = Encoding.UTF8.GetBytes("[]");
                entryStream.Write(modified, 0, modified.Length);
            }
            await Assert.ThrowsAsync<InvalidDataException>(() => archive.OpenAsync(path));
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public async Task ExcelContainsSeparateCategorySheetsPreservesNativeTypesAndTreatsFormulaLikeValuesAsText()
    {
        string directory = NewTestDirectory();
        try
        {
            string path = Path.Combine(directory, "investigation.xlsx");
            var snapshot = CarthagoSessionSnapshot.CreateEmpty();
            snapshot.AddRows("Traffic", new[]
            {
                new
                {
                    Source = "=HYPERLINK(\"https://example.test\")",
                    Length = 1148,
                    IsUdp = true
                }
            });
            await new CarthagoExcelExportService().ExportAsync(path, snapshot);

            using var document = SpreadsheetDocument.Open(path, false);
            var workbook = document.WorkbookPart!;
            string[] names = workbook.Workbook.Descendants<Sheet>().Select(s => s.Name!.Value!).ToArray();
            Assert.Equal(CarthagoSessionSnapshot.CategoryOrder.Concat(new[] { "DataQuality" }), names);

            Sheet trafficSheet = workbook.Workbook.Descendants<Sheet>().Single(s => s.Name == "Traffic");
            var part = (WorksheetPart)workbook.GetPartById(trafficSheet.Id!.Value!);
            var rows = part.Worksheet.GetFirstChild<SheetData>()!.Elements<Row>().ToArray();
            Assert.Equal(2, rows.Length);
            Assert.Equal(1U, rows[0].RowIndex!.Value);
            Assert.Equal(2U, rows[1].RowIndex!.Value);

            Cell[] header = rows[0].Elements<Cell>().ToArray();
            Cell[] data = rows[1].Elements<Cell>().ToArray();
            Assert.Equal(new[] { "A1", "B1", "C1" }, header.Select(c => c.CellReference!.Value).ToArray());
            Assert.Equal(new[] { "A2", "B2", "C2" }, data.Select(c => c.CellReference!.Value).ToArray());

            Assert.Equal(CellValues.InlineString, data[0].DataType!.Value);
            Assert.Null(data[0].CellFormula);
            Assert.Contains("=HYPERLINK", data[0].InlineString!.InnerText);

            Assert.Equal(CellValues.Number, data[1].DataType!.Value);
            Assert.Equal("1148", data[1].CellValue!.Text);

            Assert.Equal(CellValues.Boolean, data[2].DataType!.Value);
            Assert.Equal("1", data[2].CellValue!.Text);

            Pane pane = Assert.Single(part.Worksheet.Descendants<Pane>());
            Assert.Equal(PaneStateValues.Frozen, pane.State!.Value);
            Assert.Equal(1D, pane.VerticalSplit!.Value);
            Assert.Equal("A2", pane.TopLeftCell!.Value);

            AutoFilter filter = Assert.Single(part.Worksheet.Descendants<AutoFilter>());
            Assert.Equal("A1:C2", filter.Reference!.Value);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public void RuleCatalogExportIncludesAllRegisteredRulesEvenWhenNoRuleAlerted()
    {
        var rows = CarthagoRuleCatalogExport.Build(Array.Empty<Carthago.Models.DetectionEvent>());
        int expected = Carthago.Engine.Rules.Catalog.RuleRegistry.CreateDefaultRules()
            .Select(rule => rule.Descriptor.RuleId)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();

        Assert.Equal(expected, rows.Count);
        Assert.Contains(rows, row => row.RuleId == "R001");
        Assert.All(rows, row =>
        {
            Assert.Equal(0, row.ObservedEvents);
            Assert.Null(row.MostRecentUtc);
        });
    }

    [Fact]
    public void DataQualityDistinguishesNullUnknownAndRedactedValues()
    {
        var snapshot = CarthagoSessionSnapshot.CreateEmpty();
        snapshot.AddRows("Traffic", new[]
        {
            new
            {
                Source = "192.0.2.10",
                ProcessName = "Unknown",
                ProcessId = 0,
                TlsVersion = (string?)null,
                Authorization = "Bearer secret"
            }
        });

        var rows = CarthagoExcelExportService.BuildDataQualityRows(snapshot);
        JsonElement tls = rows.Single(row => row.GetProperty("Category").GetString() == "Traffic"
            && row.GetProperty("Field").GetString() == "TlsVersion");
        JsonElement processName = rows.Single(row => row.GetProperty("Category").GetString() == "Traffic"
            && row.GetProperty("Field").GetString() == "ProcessName");
        JsonElement authorization = rows.Single(row => row.GetProperty("Category").GetString() == "Traffic"
            && row.GetProperty("Field").GetString() == "Authorization");

        Assert.Equal(1, tls.GetProperty("NullOrAbsentValues").GetInt32());
        Assert.Equal(1, processName.GetProperty("UnknownSentinelValues").GetInt32());
        Assert.Equal(1, authorization.GetProperty("RedactedValues").GetInt32());
    }

    private static string NewTestDirectory()
    {
        string path = Path.Combine(Path.GetTempPath(), "carthago-csa-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
