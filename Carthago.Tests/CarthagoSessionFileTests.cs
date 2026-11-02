// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED — 0 EXECUTED.
using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
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
    public async Task ExcelContainsSeparateCategorySheetsAndTreatsFormulaLikeValuesAsText()
    {
        string directory = NewTestDirectory();
        try
        {
            string path = Path.Combine(directory, "investigation.xlsx");
            var snapshot = CarthagoSessionSnapshot.CreateEmpty();
            snapshot.AddRows("Traffic", new[] { new { Source = "=HYPERLINK(\"https://example.test\")" } });
            await new CarthagoExcelExportService().ExportAsync(path, snapshot);

            using var document = SpreadsheetDocument.Open(path, false);
            var workbook = document.WorkbookPart!;
            string[] names = workbook.Workbook.Descendants<Sheet>().Select(s => s.Name!.Value!).ToArray();
            Assert.Equal(CarthagoSessionSnapshot.CategoryOrder, names);
            Sheet trafficSheet = workbook.Workbook.Descendants<Sheet>().Single(s => s.Name == "Traffic");
            var part = (WorksheetPart)workbook.GetPartById(trafficSheet.Id!.Value!);
            var cells = part.Worksheet.Descendants<Cell>().ToArray();
            Assert.All(cells, cell => Assert.Equal(CellValues.InlineString, cell.DataType!.Value));
            Assert.Contains("=HYPERLINK", cells.Last().InlineString!.InnerText);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static string NewTestDirectory()
    {
        string path = Path.Combine(Path.GetTempPath(), "carthago-csa-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
