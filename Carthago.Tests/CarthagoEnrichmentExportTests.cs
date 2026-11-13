using System;
using System.IO;
using System.Threading.Tasks;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;
using DocumentFormat.OpenXml.Validation;
using System.Linq;
using System.Text.Json;
using Carthago.Models;
using Carthago.Services.SessionFiles;
using Xunit;

namespace Carthago.Tests;

public sealed class CarthagoEnrichmentExportTests
{
    [Fact]
    public void Projection_Preserves_Endpoint_And_Lookup_Provenance()
    {
        var record = new TrafficRecord
        {
            Source = "8.8.8.8", Destination = "192.168.1.10",
            SrcIpScope = "Public", DstIpScope = "Private", SrcIsLocalHost = false, DstIsLocalHost = true,
            SrcCountry = "United States", SrcCountryIso2 = "US", SrcAsn = 15169,
            WhoisLookupIp = "8.8.8.8", WhoisCountry = "GB",
            ReputationLookupIp = "8.8.8.8", ProcessAttribution = "UdpLocalBinding",
            ProcessId = 42, CaptureInterfaceEvidence = "WindowsInterfaceGuid",
            DnsCorrelationEvidence = "MatchedDnsQueryResponse"
        };
        var snapshot = CarthagoSessionSnapshot.CreateEmpty();
        snapshot.AddRows("Enrichment", new[] { CarthagoEnrichmentExport.Project(record) });
        var row = Assert.Single(snapshot.Categories["Enrichment"]);
        Assert.Equal(record.Id, row.GetProperty("Id").GetGuid());
        Assert.Equal("US", row.GetProperty("SrcCountryIso2").GetString());
        Assert.Equal(15169L, row.GetProperty("SrcAsn").GetInt64());
        Assert.Equal(JsonValueKind.Null, row.GetProperty("DstCountry").ValueKind);
        Assert.True(row.GetProperty("DstIsLocalHost").GetBoolean());
        Assert.Equal("8.8.8.8", row.GetProperty("WhoisLookupIp").GetString());
        Assert.Equal("GB", row.GetProperty("WhoisCountry").GetString());
        Assert.Equal("8.8.8.8", row.GetProperty("ReputationLookupIp").GetString());
        Assert.Equal("UdpLocalBinding", row.GetProperty("ProcessAttribution").GetString());
        Assert.Equal("WindowsInterfaceGuid", row.GetProperty("CaptureInterfaceEvidence").GetString());
        Assert.Equal("MatchedDnsQueryResponse", row.GetProperty("DnsCorrelationEvidence").GetString());
    }

    [Fact]
    public void Missing_Enrichment_Remains_In_Coverage_Denominator()
    {
        var snapshot = CarthagoSessionSnapshot.CreateEmpty();
        snapshot.AddRows("Enrichment", new[] { new TrafficRecord { SrcCountry = "Sweden" }, new TrafficRecord() }
            .Select(CarthagoEnrichmentExport.Project));
        Assert.Equal(2, snapshot.Categories["Enrichment"].Count);
        var quality = CarthagoExcelExportService.BuildDataQualityRows(snapshot)
            .Single(r => r.GetProperty("Category").GetString() == "Enrichment" && r.GetProperty("Field").GetString() == "SrcCountry");
        Assert.Equal(2, quality.GetProperty("Rows").GetInt32());
        Assert.Equal(1, quality.GetProperty("NullOrAbsentValues").GetInt32());
        Assert.Equal(50.0, quality.GetProperty("UsableCoveragePercent").GetDouble());
    }

    [Fact]
    public async Task Workbook_Roundtrip_Preserves_Enrichment_And_Valid_View_References()
    {
        string directory = Path.Combine(Path.GetTempPath(), "carthago-enrichment-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            string path = Path.Combine(directory, "enrichment.xlsx");
            var snapshot = CarthagoSessionSnapshot.CreateEmpty();
            snapshot.AddRows("Enrichment", new[]
            {
                new TrafficRecord { Source = "8.8.8.8", Destination = "192.168.1.10",
                    SrcCountry = "United States", SrcCountryIso2 = "US", SrcAsn = 15169,
                    SrcIsLocalHost = false, DstIsLocalHost = true,
                    WhoisLookupIp = "8.8.8.8", WhoisCountry = "GB" },
                new TrafficRecord()
            }.Select(CarthagoEnrichmentExport.Project));
            await new CarthagoExcelExportService().ExportAsync(path, snapshot);
            using var document = SpreadsheetDocument.Open(path, false);
            var workbook = document.WorkbookPart!;
            Assert.Single(workbook.Workbook.Descendants<WorkbookView>());
            foreach (var part in workbook.WorksheetParts)
                Assert.Equal(0U, Assert.Single(part.Worksheet.Descendants<SheetView>()).WorkbookViewId!.Value);
            Assert.Empty(new OpenXmlValidator().Validate(document));
            Row[] Rows(string name)
            {
                var sheet = workbook.Workbook.Descendants<Sheet>().Single(s => s.Name!.Value == name);
                return ((WorksheetPart)workbook.GetPartById(sheet.Id!.Value!))
                    .Worksheet.GetFirstChild<SheetData>()!.Elements<Row>().ToArray();
            }
            Cell At(Row[] rows, int row, string field)
            {
                int index = Array.FindIndex(rows[0].Elements<Cell>().ToArray(), c => c.InlineString!.InnerText == field);
                Assert.True(index >= 0, field);
                return rows[row].Elements<Cell>().ElementAt(index);
            }
            var enrichment = Rows("Enrichment");
            Assert.Equal(3, enrichment.Length);
            Assert.Equal("US", At(enrichment, 1, "SrcCountryIso2").InlineString!.InnerText);
            Assert.Equal("GB", At(enrichment, 1, "WhoisCountry").InlineString!.InnerText);
            Assert.Equal("8.8.8.8", At(enrichment, 1, "WhoisLookupIp").InlineString!.InnerText);
            Assert.Equal(CellValues.Number, At(enrichment, 1, "SrcAsn").DataType!.Value);
            Assert.Equal("15169", At(enrichment, 1, "SrcAsn").CellValue!.Text);
            Assert.Equal(CellValues.Boolean, At(enrichment, 1, "DstIsLocalHost").DataType!.Value);
            Assert.Equal("1", At(enrichment, 1, "DstIsLocalHost").CellValue!.Text);
            Assert.Equal("0", At(enrichment, 1, "SrcIsLocalHost").CellValue!.Text);
            Assert.Equal("", At(enrichment, 2, "SrcCountry").InlineString!.InnerText);
            var quality = Rows("DataQuality");
            int q = Enumerable.Range(1, quality.Length - 1).Single(i =>
                At(quality, i, "Category").InlineString!.InnerText == "Enrichment" &&
                At(quality, i, "Field").InlineString!.InnerText == "SrcCountry");
            Assert.Equal("2", At(quality, q, "Rows").CellValue!.Text);
            Assert.Equal("1", At(quality, q, "NullOrAbsentValues").CellValue!.Text);
            Assert.Equal(50.0, double.Parse(At(quality, q, "UsableCoveragePercent").CellValue!.Text,
                System.Globalization.CultureInfo.InvariantCulture));
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public async Task Workbook_Hostile_Text_Remains_Valid_Literal_Text()
    {
        string directory = Path.Combine(Path.GetTempPath(), "carthago-text-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            string path = Path.Combine(directory, "text.xlsx");
            string hostile = "=1+1\u0000\u0001\uFFFE\t\n😀";
            string longText = new string('a', 32754) + "😀" + new string('b', 30);
            var snapshot = CarthagoSessionSnapshot.CreateEmpty();
            snapshot.AddRows("Enrichment", new[] { new { Hostile = hostile, LongText = longText } });
            await new CarthagoExcelExportService().ExportAsync(path, snapshot);
            using var document = SpreadsheetDocument.Open(path, false);
            Assert.Empty(new OpenXmlValidator().Validate(document));
            var workbook = document.WorkbookPart!;
            var sheet = workbook.Workbook.Descendants<Sheet>().Single(s => s.Name!.Value == "Enrichment");
            var cells = ((WorksheetPart)workbook.GetPartById(sheet.Id!.Value!))
                .Worksheet.GetFirstChild<SheetData>()!.Elements<Row>().Last().Elements<Cell>().ToArray();
            Assert.Equal(CellValues.InlineString, cells[0].DataType!.Value);
            Assert.Null(cells[0].CellFormula);
            Assert.Equal("=1+1\uFFFD\uFFFD\uFFFD\t\n😀", cells[0].InlineString!.InnerText);
            string truncated = cells[1].InlineString!.InnerText;
            Assert.EndsWith(" [TRUNCATED]", truncated);
            Assert.True(truncated.Length <= 32767);
            Assert.DoesNotContain("\uFFFD", truncated);
            Assert.Equal(new string('a', 32754) + " [TRUNCATED]", truncated);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public void Inline_Text_Repairs_Unpaired_Surrogates_And_Preserves_Valid_Pairs()
    {
        Assert.Equal("�😀�", CarthagoExcelExportService.PrepareInlineText("\uD800😀\uDC00"));
    }
}
