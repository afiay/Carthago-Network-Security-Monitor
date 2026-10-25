using Carthago.Models;
using Carthago.Services;
using Carthago.Views;

namespace Carthago.Tests;

public sealed class DnsVolumeEvidenceTests
{
    [Fact]
    public void OrdinaryResolverBurst_IsVolumeAnomaly_NotHighSeverityTunneling()
    {
        var source = $"2001:db8::{Random.Shared.Next(1, 65535):x}";
        var findings = new List<DetectionEvent>();
        var matchedDnsVolume = false;
        var shadowedDnsVolume = false;
        var suppressedDnsVolume = false;

        for (var i = 0; i < 34; i++)
        {
            findings.AddRange(RuleEngine.Evaluate(new TrafficRecord
            {
                Source = source,
                Destination = "2001:2000::248",
                DestinationPort = 53,
                Protocol = "DNS",
                DnsQname = "updates.example.org",
                DnsQtype = "AAAA",
                Info = "Standard DNS query"
            }, Sensitivity.Balanced).Where(d => d.RuleId == "R006"));
            var trace = RuleEngine.LastEvaluationTrace;
            matchedDnsVolume |= trace?.MatchedRuleIds.Contains("R006") == true;
            shadowedDnsVolume |= trace?.ShadowedRuleIds.Contains("R006") == true;
            suppressedDnsVolume |= trace?.SuppressedRuleIds.Contains("R006") == true;
        }

        Assert.True(matchedDnsVolume, "Normal DNS volume should match R006 before tuning and suppression.");
        Assert.True(shadowedDnsVolume || suppressedDnsVolume || findings.Count > 0,
            "R006 should be emitted or carry an explicit shadow/suppression decision.");
        foreach (var finding in findings)
        {
            Assert.Equal(SeverityLevel.Medium, finding.Severity);
            Assert.Contains("DNS request volume", finding.Description);
            Assert.DoesNotContain("tunneling", finding.Description, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void HighVolumeWithLongEncodedQueries_RetainsTunnelingWarning()
    {
        var source = $"2001:db8::{Random.Shared.Next(1, 65535):x}";
        var findings = new List<DetectionEvent>();
        var encodedQuery = "a7f4b31e9d02c85f67a0134d8e2b9c0f7a1e6d45b83c09af2d71e6c4.example.org";

        for (var i = 0; i < 34; i++)
        {
            findings.AddRange(RuleEngine.Evaluate(new TrafficRecord
            {
                Source = source,
                Destination = "2001:db8::53",
                DestinationPort = 53,
                Protocol = "DNS",
                DnsQname = encodedQuery,
                DnsQtype = "TXT",
                Info = "Standard DNS query"
            }, Sensitivity.Balanced).Where(d => d.RuleId == "R006"));
        }

        var finding = Assert.Single(findings);
        Assert.Equal(SeverityLevel.High, finding.Severity);
        Assert.Contains("tunneling", finding.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("high-entropy/long query", finding.Description);
    }

    [Fact]
    public void DetectionOnlyDnsVolume_DoesNotClaimExternalIocOrFeedMatch()
    {
        var vm = ThreatMatchVm.FromDetection(new DetectionEvent
        {
            RuleId = "R006",
            Description = "Elevated DNS request volume (34/30s)",
            SourceIp = "2001:db8::42",
            DestinationIp = "2001:2000::248",
            Country = "SE",
            Severity = SeverityLevel.Medium
        }, null);

        Assert.Equal("DNS Activity", vm.Classification);
        Assert.Equal("Observed", vm.FeedState);
        Assert.DoesNotContain("External IOC", vm.Tags);
        Assert.Contains(vm.Evidence, item => item.Contains("no external threat-feed match", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain("Suspicious", vm.Title, StringComparison.OrdinalIgnoreCase);
    }
}
