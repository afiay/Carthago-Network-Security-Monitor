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
}
