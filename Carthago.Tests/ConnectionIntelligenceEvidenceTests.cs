using System.Linq;
using Carthago.Models;
using Carthago.Services;
using Carthago.Views;

namespace Carthago.Tests;

public sealed class ConnectionIntelligenceEvidenceTests
{
    [Fact]
    public void Endpoint_Provenance_Is_Not_Assumed_To_Be_Destination()
    {
        var record = new TrafficRecord
        {
            Source = "8.8.8.8", Destination = "192.168.1.10",
            WhoisLookupIp = "::ffff:8.8.8.8", ReputationLookupIp = "192.168.1.10",
            ReputationEnrichmentStatus = "Success", ReputationScore = 0,
            VpnClassificationIp = "1.1.1.1"
        };
        var fields = ConnectionIntelligenceEvidence.Build(record).ToDictionary(x => x.Key, x => x.Value);
        Assert.Equal("Source endpoint", fields["WHOIS · endpoint provenance"]);
        Assert.Equal("Destination endpoint", fields["Reputation · endpoint provenance"]);
        Assert.Equal("Other endpoint", fields["VPN inference · endpoint provenance"]);
        Assert.Equal("0", fields["Reputation · abuse score"]);
    }

    [Fact]
    public void Missing_And_Timed_Out_Providers_Do_Not_Assert_Clean_Identity()
    {
        var record = new TrafficRecord { ReputationEnrichmentStatus = "TimedOut", ReputationScore = 0 };
        var fields = ConnectionIntelligenceEvidence.Build(record).ToDictionary(x => x.Key, x => x.Value);
        Assert.Equal("TimedOut", fields["Reputation · status"]);
        Assert.False(fields.ContainsKey("Reputation · abuse score"));
        Assert.False(fields.ContainsKey("VPN inference · heuristic score"));
    }

    [Fact]
    public void Inspector_Separates_Observed_And_Correlated_Tls()
    {
        var record = new TrafficRecord
        {
            Sni = "packet.example", TlsCorrelatedSni = "flow.example",
            DnsCorrelatedNames = "a.example; b.example", DnsCorrelatedNameCount = 2,
            CaptureTunnelHint = "WireGuard", ProcessName = "chrome",
            TlsObservedNegotiatedVersion = "TLS1.3", TlsVersion = "TLS1.2"
        };
        var fields = NetworkInvestigationPage.BuildTrafficEvidence(record).ToDictionary(x => x.Key, x => x.Value);
        Assert.Equal("packet.example", fields["Application · TLS SNI"]);
        Assert.Equal("flow.example", fields["TLS correlation · SNI"]);
        Assert.Equal("TLS1.3", fields["TLS observed · negotiated version"]);
        Assert.Equal("TLS1.2", fields["Application · TLS version"]);
        Assert.Equal("2", fields["DNS correlation · candidate count"]);
        Assert.Equal("chrome", fields["Host · process name"]);
        Assert.Equal("WireGuard", fields["Capture · tunnel hint (observation point)"]);
        Assert.Equal("packet.example", record.Sni);
    }

    [Fact]
    public void Search_And_Highlight_Identify_Correlation_Not_Raw_Packet()
    {
        var record = new TrafficRecord { DnsCorrelatedNames = "shared.example", TlsCorrelatedSni = "shared.example" };
        Assert.True(NetworkInvestigationPage.MatchesTrafficText(record, "shared.example"));
        var matches = NetworkInvestigationPage.TrafficMatchFields(record, "shared.example");
        Assert.Equal(new[] { "DNS correlated candidates", "TLS correlated SNI" }, matches);
        Assert.Equal(new[] { "DNS correlation · candidate names", "TLS correlation · SNI" },
            NetworkInvestigationPage.HighlightEvidenceKeys("traffic", matches));
    }

    [Fact]
    public void No_Enrichment_Does_Not_Invent_Fields()
    {
        Assert.Empty(ConnectionIntelligenceEvidence.Build(new TrafficRecord()));
    }
}
