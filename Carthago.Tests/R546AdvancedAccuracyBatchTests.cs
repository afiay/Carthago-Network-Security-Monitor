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

public sealed class R546AdvancedAccuracyBatchTests
{
    private static readonly DateTime Origin = new(2026, 11, 1, 15, 0, 0, DateTimeKind.Utc);

    private static TrafficRecord Sample(string source = "10.45.0.20", string destination = "8.8.8.8")
        => new()
        {
            Id = Guid.NewGuid(), Source = source, Destination = destination,
            Protocol = "UDP", IsUdp = true, IsTcp = false, IpVersion = 4,
            SourcePort = 40000, DestinationPort = 123,
            ApplicationProtocol = "ntp.mode7.monlist", ApplicationService = "NTP",
            Length = 60, L4Len = 8, Info = string.Empty
        };

    private static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    private static async Task<RuleEvaluationResult> Three(
        R546_NtpMonlistOutboundTargetFanoutRule rule,
        TrafficRecord first, TrafficRecord second, TrafficRecord third)
    {
        Assert.False((await rule.EvaluateAsync(At(first))).Matched);
        Assert.False((await rule.EvaluateAsync(At(second, 1))).Matched);
        return await rule.EvaluateAsync(At(third, 2));
    }

    [Fact]
    public void Actual_Packet_Producer_Classifies_Mode7_Monlist_Prefix()
    {
        byte[] datagram = { 0x27, 0x00, 0x03, 0x2a, 0, 0, 0, 0 };
        Assert.True(OtProtocolLight.TryIdentifyUdp(datagram, 40000, 123, out var operation));
        Assert.Equal("ntp.mode7.monlist", operation);
    }

    [Fact]
    public void Truncated_Or_Spoofed_Mode7_Header_Fails_Parser()
    {
        byte[] truncated = { 0x27, 0x00, 0x03, 0x2a, 0, 0, 0 };
        byte[] response = { 0x27, 0x80, 0x03, 0x2a, 0, 0, 0, 0 };
        byte[] sync = { 0x23, 0x00, 0x03, 0x2a, 0, 0, 0, 0 };
        Assert.False(OtProtocolLight.TryIdentifyUdp(truncated, 40000, 123, out _));
        Assert.False(OtProtocolLight.TryIdentifyUdp(response, 40000, 123, out _));
        Assert.False(OtProtocolLight.TryIdentifyUdp(sync, 40000, 123, out _));
    }

    [Fact]
    public async Task Three_Distinct_Public_Targets_Produce_One_Candidate()
    {
        var result = await Three(new R546_NtpMonlistOutboundTargetFanoutRule(),
            Sample(destination: "8.8.8.8"), Sample(destination: "1.1.1.1"),
            Sample(destination: "9.9.9.9"));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R546", evt.RuleId);
        Assert.Equal(3, evt.Count);
        Assert.Equal(300, evt.WindowSeconds);
        Assert.Equal(SeverityLevel.Medium, evt.Severity);
    }

    [Theory]
    [InlineData("192.0.2.1")]
    [InlineData("198.51.100.2")]
    [InlineData("203.0.113.3")]
    [InlineData("198.18.0.5")]
    public async Task NonPublic_Target_Is_Not_A_Distinct_Public_Endpoint(string destination)
    {
        var rule = new R546_NtpMonlistOutboundTargetFanoutRule();
        Assert.False((await Three(rule, Sample(destination: "8.8.8.8"),
            Sample(destination: "1.1.1.1"), Sample(destination: destination))).Matched);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.1.10")]
    [InlineData("192.0.2.15")]
    public async Task NonRfc1918_Source_Cannot_Trigger(string source)
    {
        Assert.False((await Three(new R546_NtpMonlistOutboundTargetFanoutRule(),
            Sample(source, "8.8.8.8"), Sample(source, "1.1.1.1"),
            Sample(source, "9.9.9.9"))).Matched);
    }

    [Fact]
    public async Task Normal_Ntp_Synchronization_Does_Not_Match()
    {
        var a = Sample(destination: "8.8.8.8"); a.ApplicationProtocol = "ntp";
        var b = Sample(destination: "1.1.1.1"); b.ApplicationProtocol = "ntp";
        var c = Sample(destination: "9.9.9.9"); c.ApplicationProtocol = "ntp";
        Assert.False((await Three(new R546_NtpMonlistOutboundTargetFanoutRule(), a, b, c)).Matched);
    }

    [Fact]
    public async Task Port_And_Info_Only_Cannot_Spoof_Parsed_Operation()
    {
        var a = Sample(destination: "8.8.8.8"); a.ApplicationProtocol = null; a.Info = "ntp.mode7.monlist token=secret";
        var b = Sample(destination: "1.1.1.1"); b.ApplicationProtocol = null; b.Info = "ntp.mode7.monlist";
        var c = Sample(destination: "9.9.9.9"); c.ApplicationProtocol = null; c.Info = "ntp.mode7.monlist";
        Assert.False((await Three(new R546_NtpMonlistOutboundTargetFanoutRule(), a, b, c)).Matched);
    }

    [Fact]
    public async Task Repeated_Same_Destination_Does_Not_Count_As_Fanout()
    {
        var result = await Three(new R546_NtpMonlistOutboundTargetFanoutRule(),
            Sample(), Sample(), Sample());
        Assert.False(result.Matched);
    }

    [Fact]
    public async Task Wrong_Transport_Direction_Or_Port_Fails_Closed()
    {
        var rule = new R546_NtpMonlistOutboundTargetFanoutRule();
        var tcp = Sample(); tcp.IsUdp = false; tcp.IsTcp = true; tcp.Protocol = "TCP";
        var response = Sample(); response.SourcePort = 123; response.DestinationPort = 40000;
        var wrongPort = Sample(); wrongPort.DestinationPort = 124;
        Assert.False((await rule.EvaluateAsync(At(tcp))).Matched);
        Assert.False((await rule.EvaluateAsync(At(response, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(wrongPort, 2))).Matched);
    }

    [Fact]
    public async Task Contradictory_Tls_Dns_And_Http_Metadata_Fails_Closed()
    {
        var rule = new R546_NtpMonlistOutboundTargetFanoutRule();
        var tls = Sample(); tls.TlsVersion = "TLS1.3";
        var dns = Sample(); dns.DnsQname = "example.test";
        var http = Sample(); http.HttpUri = "/login";
        Assert.False((await rule.EvaluateAsync(At(tls))).Matched);
        Assert.False((await rule.EvaluateAsync(At(dns, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(http, 2))).Matched);
    }

    [Fact]
    public async Task Missing_Or_Inconsistent_Length_And_IpVersion_Fails_Closed()
    {
        var rule = new R546_NtpMonlistOutboundTargetFanoutRule();
        var missing = Sample(); missing.L4Len = null;
        var tooShort = Sample(); tooShort.L4Len = 7;
        var tooLong = Sample(); tooLong.L4Len = 513;
        var ipv6 = Sample(); ipv6.IpVersion = 6;
        Assert.False((await rule.EvaluateAsync(At(missing))).Matched);
        Assert.False((await rule.EvaluateAsync(At(tooShort, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(tooLong, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(ipv6, 3))).Matched);
    }

    [Fact]
    public async Task Duplicate_Packet_Id_Cannot_Complete_Three_Targets()
    {
        var rule = new R546_NtpMonlistOutboundTargetFanoutRule();
        var first = Sample(destination: "8.8.8.8");
        var second = Sample(destination: "1.1.1.1"); second.Id = first.Id;
        Assert.False((await rule.EvaluateAsync(At(first))).Matched);
        Assert.False((await rule.EvaluateAsync(At(second, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "9.9.9.9"), 2))).Matched);
    }

    [Fact]
    public async Task Out_Of_Order_Observation_Cannot_Complete_Fanout()
    {
        var rule = new R546_NtpMonlistOutboundTargetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "8.8.8.8"), 30))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "1.1.1.1"), 10))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "9.9.9.9"), 31))).Matched);
    }

    [Fact]
    public async Task Separate_Sources_Do_Not_Share_Distinct_Target_Counts()
    {
        var rule = new R546_NtpMonlistOutboundTargetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Sample("10.45.0.20", "8.8.8.8")))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample("10.45.0.21", "1.1.1.1"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample("10.45.0.20", "9.9.9.9"), 2))).Matched);
    }

    [Fact]
    public async Task Expired_Window_Does_Not_Recycle_Old_Targets()
    {
        var rule = new R546_NtpMonlistOutboundTargetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "8.8.8.8")))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "1.1.1.1"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "9.9.9.9"), 302))).Matched);
    }

    [Fact]
    public async Task Cooldown_Returns_Suppressed_Match_Without_Second_Event()
    {
        var rule = new R546_NtpMonlistOutboundTargetFanoutRule();
        Assert.True((await Three(rule, Sample(destination: "8.8.8.8"),
            Sample(destination: "1.1.1.1"), Sample(destination: "9.9.9.9"))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "8.8.8.8"), 303))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "1.1.1.1"), 304))).Matched);
        var result = await rule.EvaluateAsync(At(Sample(destination: "9.9.9.9"), 305));
        Assert.True(result.Suppressed);
        Assert.Empty(result.Events);
    }

    [Fact]
    public async Task Raw_Info_And_Sensitive_Strings_Never_Enter_Event()
    {
        var a = Sample(destination: "8.8.8.8"); a.Info = "password=secret-marker";
        var b = Sample(destination: "1.1.1.1"); b.Info = "token=secret-marker";
        var c = Sample(destination: "9.9.9.9"); c.Info = "secret-marker";
        var result = await Three(new R546_NtpMonlistOutboundTargetFanoutRule(), a, b, c);
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains("secret-marker", StringComparison.Ordinal));
    }

    [Fact]
    public void Unique_Registry_Entry_Has_Candidate_Shadow_Policy()
    {
        var rule = new R546_NtpMonlistOutboundTargetFanoutRule();
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(80, rule.PrecisionProfile.MinimumConfidence);
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Single(RuleRegistry.CreateDefaultRules().Where(r => r.Descriptor.RuleId == "R546"));
        Assert.True(RulePrecisionCatalog.Validate("R546", Sample()).CanEvaluate);
    }
}
