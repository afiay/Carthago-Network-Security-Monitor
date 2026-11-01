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

public sealed class R545AdvancedAccuracyBatchTests
{
    private static readonly DateTime Origin = new(2026, 11, 1, 12, 0, 0, DateTimeKind.Utc);

    private static TrafficRecord Sample(string source = "8.8.8.8", string destination = "10.45.0.20")
        => new()
        {
            Id = Guid.NewGuid(), Source = source, Destination = destination,
            Protocol = "UDP", IsUdp = true, IsTcp = false,
            SourcePort = 47808, DestinationPort = 47808,
            ApplicationProtocol = "bacnet.iam", ApplicationService = "BACnet",
            Length = 96, L4Len = 8, Info = string.Empty
        };

    private static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    private static async Task<RuleEvaluationResult> Two(
        R545_ExternalBacnetIAmAnnouncementRule rule, TrafficRecord first, TrafficRecord second)
    {
        Assert.False((await rule.EvaluateAsync(At(first))).Matched);
        return await rule.EvaluateAsync(At(second, 1));
    }

    [Fact]
    public async Task Parsed_External_IAm_Pair_Produces_One_Candidate()
    {
        var result = await Two(new R545_ExternalBacnetIAmAnnouncementRule(), Sample(), Sample());
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R545", evt.RuleId);
        Assert.Equal(2, evt.Count);
        Assert.Equal(300, evt.WindowSeconds);
    }

    [Fact]
    public void Existing_Packet_Producer_Classifies_Bounded_IAm()
    {
        byte[] datagram = { 0x81, 0x0a, 0x00, 0x08, 0x01, 0x00, 0x10, 0x00 };
        Assert.True(OtProtocolLight.TryIdentifyUdp(datagram, 47808, 47808, out var operation));
        Assert.Equal("bacnet.iam", operation);
    }

    [Fact]
    public void Truncated_Or_Inconsistent_Wire_Data_Is_Rejected()
    {
        byte[] truncated = { 0x81, 0x0a, 0x00, 0x08, 0x01, 0x00, 0x10 };
        byte[] wrongLength = { 0x81, 0x0a, 0x00, 0x09, 0x01, 0x00, 0x10, 0x00 };
        Assert.False(OtProtocolLight.TryIdentifyUdp(truncated, 47808, 47808, out _));
        Assert.False(OtProtocolLight.TryIdentifyUdp(wrongLength, 47808, 47808, out _));
    }

    [Theory]
    [InlineData("10.10.10.10")]
    [InlineData("192.0.2.8")]
    [InlineData("198.51.100.8")]
    [InlineData("203.0.113.8")]
    [InlineData("198.18.0.8")]
    public async Task Internal_Or_NonRoutable_Source_Is_Benign(string source)
    {
        var result = await Two(new R545_ExternalBacnetIAmAnnouncementRule(),
            Sample(source: source), Sample(source: source));
        Assert.False(result.Matched);
    }

    [Theory]
    [InlineData("bacnet.whois")]
    [InlineData("bacnet")]
    [InlineData("BACnet-I-Am")]
    public async Task Other_Protocol_Or_Operation_Is_Not_An_IAm(string operation)
    {
        var first = Sample(); first.ApplicationProtocol = operation;
        var second = Sample(); second.ApplicationProtocol = operation;
        Assert.False((await Two(new R545_ExternalBacnetIAmAnnouncementRule(), first, second)).Matched);
    }

    [Fact]
    public async Task Legitimate_Internal_Device_Announcement_Is_Not_A_Match()
    {
        Assert.False((await Two(new R545_ExternalBacnetIAmAnnouncementRule(),
            Sample("10.45.0.10"), Sample("10.45.0.10"))).Matched);
    }

    [Fact]
    public async Task Packet_Info_And_Port_Only_Cannot_Spoof_Operation()
    {
        var a = Sample(); a.ApplicationProtocol = null; a.Info = "bacnet.iam device=admin";
        var b = Sample(); b.ApplicationProtocol = null; b.Info = "bacnet.iam device=admin";
        Assert.False((await Two(new R545_ExternalBacnetIAmAnnouncementRule(), a, b)).Matched);
    }

    [Fact]
    public async Task Wrong_Destination_Port_Does_Not_Qualify()
    {
        var a = Sample(); a.DestinationPort = 47809;
        var b = Sample(); b.DestinationPort = 47809;
        Assert.False((await Two(new R545_ExternalBacnetIAmAnnouncementRule(), a, b)).Matched);
    }

    [Fact]
    public async Task Tcp_Tls_Or_Dns_Contradictions_Fail_Closed()
    {
        var a = Sample(); a.IsTcp = true; a.IsUdp = false; a.Protocol = "TCP";
        var b = Sample(); b.TlsVersion = "TLS1.3";
        var c = Sample(); c.DnsQname = "example.test";
        var d = Sample(); d.Sni = "sensitive.example";
        var rule = new R545_ExternalBacnetIAmAnnouncementRule();
        Assert.False((await rule.EvaluateAsync(At(a))).Matched);
        Assert.False((await rule.EvaluateAsync(At(b, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(c, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(d, 3))).Matched);
    }

    [Fact]
    public async Task Duplicate_Packet_Id_Cannot_Complete_Threshold()
    {
        var rule = new R545_ExternalBacnetIAmAnnouncementRule();
        var packet = Sample();
        Assert.False((await rule.EvaluateAsync(At(packet))).Matched);
        Assert.False((await rule.EvaluateAsync(At(packet, 1))).Matched);
    }

    [Fact]
    public async Task Out_Of_Order_Packet_Cannot_Complete_Threshold()
    {
        var rule = new R545_ExternalBacnetIAmAnnouncementRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(), 30))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 10))).Matched);
    }

    [Fact]
    public async Task Different_Destination_Does_Not_Complete_Window()
    {
        var rule = new R545_ExternalBacnetIAmAnnouncementRule();
        Assert.False((await rule.EvaluateAsync(At(Sample()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.45.0.21"), 1))).Matched);
    }

    [Fact]
    public async Task Window_Expiry_Does_Not_Reuse_Stale_Observation()
    {
        var rule = new R545_ExternalBacnetIAmAnnouncementRule();
        Assert.False((await rule.EvaluateAsync(At(Sample()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 301))).Matched);
    }

    [Fact]
    public async Task Cooldown_Reports_Suppressed_Match_Without_Another_Event()
    {
        var rule = new R545_ExternalBacnetIAmAnnouncementRule();
        Assert.True((await Two(rule, Sample(), Sample())).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 302))).Matched);
        var second = await rule.EvaluateAsync(At(Sample(), 303));
        Assert.True(second.Suppressed);
        Assert.Empty(second.Events);
    }

    [Fact]
    public async Task Raw_Info_And_Device_Identifiers_Never_Enter_Event_Evidence()
    {
        var first = Sample(); first.Info = "password=secret-marker device-instance=999";
        var second = Sample(); second.Info = "password=secret-marker device-instance=999";
        var result = await Two(new R545_ExternalBacnetIAmAnnouncementRule(), first, second);
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain("device-instance", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains("secret-marker", StringComparison.Ordinal)
                || item.Value.Contains("device-instance", StringComparison.Ordinal));
    }

    [Fact]
    public void Rule_Is_Registered_With_Shadow_Mode_And_Explicit_Confidence_Floor()
    {
        var rule = new R545_ExternalBacnetIAmAnnouncementRule();
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(80, rule.PrecisionProfile.MinimumConfidence);
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Single(RuleRegistry.CreateDefaultRules().Where(r => r.Descriptor.RuleId == "R545"));
        Assert.True(RulePrecisionCatalog.Validate("R545", Sample()).CanEvaluate);
    }
}
