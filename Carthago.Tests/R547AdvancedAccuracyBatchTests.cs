// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public sealed class R547AdvancedAccuracyBatchTests
{
    private static readonly DateTime Origin = new(2026, 11, 1, 19, 0, 0, DateTimeKind.Utc);

    private static TrafficRecord Sample(string source = "8.8.8.8", string destination = "10.45.0.20")
        => new()
        {
            Id = Guid.NewGuid(), Source = source, Destination = destination,
            Protocol = "UDP", IsUdp = true, IsTcp = false, IpVersion = 4,
            SourcePort = 47808, DestinationPort = 47808,
            ApplicationProtocol = "bacnet.whois", ApplicationService = "BACnet",
            Length = 96, L4Len = 8, Info = string.Empty
        };

    private static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    private static async Task<RuleEvaluationResult> Three(
        R547_ExternalBacnetWhoIsTargetFanoutRule rule,
        TrafficRecord first, TrafficRecord second, TrafficRecord third)
    {
        Assert.False((await rule.EvaluateAsync(At(first))).Matched);
        Assert.False((await rule.EvaluateAsync(At(second, 1))).Matched);
        return await rule.EvaluateAsync(At(third, 2));
    }

    [Fact]
    public void Existing_Packet_Producer_Recognizes_Bounded_WhoIs()
    {
        byte[] datagram = { 0x81, 0x0a, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08 };
        Assert.True(OtProtocolLight.TryIdentifyUdp(datagram, 47808, 47808, out var operation));
        Assert.Equal("bacnet.whois", operation);
    }

    [Fact]
    public void Truncated_And_Length_Spoofed_Wire_Requests_Are_Rejected()
    {
        byte[] truncated = { 0x81, 0x0a, 0x00, 0x08, 0x01, 0x00, 0x10 };
        byte[] badLength = { 0x81, 0x0a, 0x00, 0x09, 0x01, 0x00, 0x10, 0x08 };
        Assert.False(OtProtocolLight.TryIdentifyUdp(truncated, 47808, 47808, out _));
        Assert.False(OtProtocolLight.TryIdentifyUdp(badLength, 47808, 47808, out _));
    }

    [Fact]
    public async Task Three_Distinct_Private_Targets_Produce_One_Shadow_Candidate()
    {
        var result = await Three(new R547_ExternalBacnetWhoIsTargetFanoutRule(),
            Sample(destination: "10.45.0.20"), Sample(destination: "10.45.1.20"),
            Sample(destination: "10.45.2.20"));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R547", evt.RuleId);
        Assert.Equal(3, evt.Count);
        Assert.Equal(300, evt.WindowSeconds);
        Assert.Equal(SeverityLevel.High, evt.Severity);
    }

    [Theory]
    [InlineData("bacnet.iam")]
    [InlineData("bacnet")]
    [InlineData("BACnet-WhoIs")]
    public async Task NonWhoIs_Or_Guessed_Operation_Is_Not_Evidence(string operation)
    {
        var a = Sample(destination: "10.45.0.20"); a.ApplicationProtocol = operation;
        var b = Sample(destination: "10.45.1.20"); b.ApplicationProtocol = operation;
        var c = Sample(destination: "10.45.2.20"); c.ApplicationProtocol = operation;
        Assert.False((await Three(new R547_ExternalBacnetWhoIsTargetFanoutRule(), a, b, c)).Matched);
    }

    [Theory]
    [InlineData("192.0.2.8")]
    [InlineData("198.51.100.8")]
    [InlineData("203.0.113.8")]
    [InlineData("198.18.0.8")]
    [InlineData("10.45.0.8")]
    public async Task NonPublic_Source_Is_Not_A_Qualified_External_Scanner(string source)
    {
        Assert.False((await Three(new R547_ExternalBacnetWhoIsTargetFanoutRule(),
            Sample(source, "10.45.0.20"), Sample(source, "10.45.1.20"),
            Sample(source, "10.45.2.20"))).Matched);
    }

    [Fact]
    public async Task Internal_Commissioning_And_One_Target_Do_Not_Match()
    {
        var rule = new R547_ExternalBacnetWhoIsTargetFanoutRule();
        Assert.False((await Three(rule,
            Sample("10.45.0.8", "10.45.0.20"),
            Sample("10.45.0.8", "10.45.0.21"),
            Sample("10.45.0.8", "10.45.0.22"))).Matched);
        Assert.False((await Three(new R547_ExternalBacnetWhoIsTargetFanoutRule(),
            Sample(), Sample(), Sample())).Matched);
    }

    [Fact]
    public async Task Port_And_Freeform_Info_Cannot_Forge_WhoIs()
    {
        var a = Sample(destination: "10.45.0.20"); a.ApplicationProtocol = null; a.Info = "bacnet.whois password=secret";
        var b = Sample(destination: "10.45.1.20"); b.ApplicationProtocol = null; b.Info = "bacnet.whois";
        var c = Sample(destination: "10.45.2.20"); c.ApplicationProtocol = null; c.Info = "bacnet.whois";
        Assert.False((await Three(new R547_ExternalBacnetWhoIsTargetFanoutRule(), a, b, c)).Matched);
    }

    [Fact]
    public async Task Public_And_Multicast_Destinations_Do_Not_Qualify()
    {
        var rule = new R547_ExternalBacnetWhoIsTargetFanoutRule();
        var a = Sample(destination: "8.8.4.4");
        var b = Sample(destination: "224.0.1.1");
        var c = Sample(destination: "255.255.255.255");
        Assert.False((await rule.EvaluateAsync(At(a))).Matched);
        Assert.False((await rule.EvaluateAsync(At(b, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(c, 2))).Matched);
    }

    [Fact]
    public async Task Wrong_Transport_And_Port_Are_Not_Qualified()
    {
        var rule = new R547_ExternalBacnetWhoIsTargetFanoutRule();
        var tcp = Sample(); tcp.IsUdp = false; tcp.IsTcp = true; tcp.Protocol = "TCP";
        var wrongSrc = Sample(); wrongSrc.SourcePort = 40000;
        var wrongDst = Sample(); wrongDst.DestinationPort = 47809;
        Assert.False((await rule.EvaluateAsync(At(tcp))).Matched);
        Assert.False((await rule.EvaluateAsync(At(wrongSrc, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(wrongDst, 2))).Matched);
    }

    [Fact]
    public async Task Contradictory_Application_Metadata_Fails_Closed()
    {
        var rule = new R547_ExternalBacnetWhoIsTargetFanoutRule();
        var tls = Sample(); tls.TlsVersion = "TLS1.3";
        var dns = Sample(); dns.DnsQname = "example.test";
        var http = Sample(); http.HttpUri = "/admin";
        var headers = Sample(); headers.HttpRequestHeaders = "authorization: token";
        Assert.False((await rule.EvaluateAsync(At(tls))).Matched);
        Assert.False((await rule.EvaluateAsync(At(dns, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(http, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(headers, 3))).Matched);
    }

    [Fact]
    public async Task Missing_Or_Invalid_Ip_And_Payload_Length_Fails_Closed()
    {
        var rule = new R547_ExternalBacnetWhoIsTargetFanoutRule();
        var noLen = Sample(); noLen.L4Len = null;
        var shortLen = Sample(); shortLen.L4Len = 7;
        var longLen = Sample(); longLen.L4Len = 1477;
        var ipv6 = Sample(); ipv6.IpVersion = 6;
        Assert.False((await rule.EvaluateAsync(At(noLen))).Matched);
        Assert.False((await rule.EvaluateAsync(At(shortLen, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(longLen, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(ipv6, 3))).Matched);
    }

    [Fact]
    public async Task Duplicate_Packet_Id_Does_Not_Complete_Target_Fanout()
    {
        var rule = new R547_ExternalBacnetWhoIsTargetFanoutRule();
        var first = Sample(destination: "10.45.0.20");
        var duplicate = Sample(destination: "10.45.1.20"); duplicate.Id = first.Id;
        Assert.False((await rule.EvaluateAsync(At(first))).Matched);
        Assert.False((await rule.EvaluateAsync(At(duplicate, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.45.2.20"), 2))).Matched);
    }

    [Fact]
    public async Task Out_Of_Order_Observation_Does_Not_Complete_Threshold()
    {
        var rule = new R547_ExternalBacnetWhoIsTargetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.45.0.20"), 30))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.45.1.20"), 10))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.45.2.20"), 31))).Matched);
    }

    [Fact]
    public async Task Distinct_Public_Sources_Cannot_Combine_Target_Counts()
    {
        var rule = new R547_ExternalBacnetWhoIsTargetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Sample("8.8.8.8", "10.45.0.20"))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample("1.1.1.1", "10.45.1.20"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample("8.8.8.8", "10.45.2.20"), 2))).Matched);
    }

    [Fact]
    public async Task Expired_Observation_Window_Does_Not_Recycle_Targets()
    {
        var rule = new R547_ExternalBacnetWhoIsTargetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.45.0.20"))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.45.1.20"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.45.2.20"), 302))).Matched);
    }

    [Fact]
    public async Task Cooldown_Suppresses_Repeated_Three_Target_Fanout()
    {
        var rule = new R547_ExternalBacnetWhoIsTargetFanoutRule();
        Assert.True((await Three(rule, Sample(destination: "10.45.0.20"),
            Sample(destination: "10.45.1.20"), Sample(destination: "10.45.2.20"))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.45.0.20"), 303))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.45.1.20"), 304))).Matched);
        var result = await rule.EvaluateAsync(At(Sample(destination: "10.45.2.20"), 305));
        Assert.True(result.Suppressed);
        Assert.Empty(result.Events);
    }

    [Fact]
    public async Task Concurrent_Unique_Packets_Produce_At_Most_One_Match()
    {
        var rule = new R547_ExternalBacnetWhoIsTargetFanoutRule();
        var tasks = new[]
        {
            rule.EvaluateAsync(At(Sample(destination: "10.45.0.20"))).AsTask(),
            rule.EvaluateAsync(At(Sample(destination: "10.45.1.20"))).AsTask(),
            rule.EvaluateAsync(At(Sample(destination: "10.45.2.20"))).AsTask()
        };
        var results = await Task.WhenAll(tasks);
        Assert.Single(results.Where(result => result.Matched));
    }

    [Fact]
    public async Task Raw_Info_And_Device_Identifiers_Are_Not_Persisted()
    {
        var a = Sample(destination: "10.45.0.20"); a.Info = "password=secret-marker device=987";
        var b = Sample(destination: "10.45.1.20"); b.Info = "token=secret-marker";
        var c = Sample(destination: "10.45.2.20"); c.Info = "secret-marker";
        var result = await Three(new R547_ExternalBacnetWhoIsTargetFanoutRule(), a, b, c);
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains("secret-marker", StringComparison.Ordinal)
                || item.Value.Contains("device=987", StringComparison.Ordinal));
    }

    [Fact]
    public void Registered_Rule_Has_Candidate_Shadow_Policy()
    {
        var rule = new R547_ExternalBacnetWhoIsTargetFanoutRule();
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(80, rule.PrecisionProfile.MinimumConfidence);
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Single(RuleRegistry.CreateDefaultRules().Where(r => r.Descriptor.RuleId == "R547"));
        Assert.True(RulePrecisionCatalog.Validate("R547", Sample()).CanEvaluate);
    }
}
