// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed.
// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Net;
using SharpPcap;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public sealed class R552AdvancedAccuracyBatchTests
{
    private static readonly DateTime Origin = new(2026, 11, 1, 15, 0, 0, DateTimeKind.Utc);

    private static TrafficRecord Sample(string source = "8.8.8.8", string destination = "10.45.1.20")
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
        R552_ExternalNtpMonlistPrivateSubnetFanoutRule rule,
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
    public async Task Three_Distinct_Private_Subnets_Produce_One_Candidate()
    {
        var result = await Three(new R552_ExternalNtpMonlistPrivateSubnetFanoutRule(),
            Sample(destination: "10.45.1.20"), Sample(destination: "10.46.2.20"),
            Sample(destination: "192.168.3.20"));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R552", evt.RuleId);
        Assert.Equal(3, evt.Count);
        Assert.Equal(300, evt.WindowSeconds);
        Assert.Equal(SeverityLevel.Medium, evt.Severity);
    }

    [Theory]
    [InlineData("192.0.2.1")]
    [InlineData("198.51.100.2")]
    [InlineData("203.0.113.3")]
    [InlineData("198.18.0.5")]
    [InlineData("8.8.8.8")]
    public async Task NonPrivate_Target_Is_Not_A_Distinct_Private_Subnet(string destination)
    {
        var rule = new R552_ExternalNtpMonlistPrivateSubnetFanoutRule();
        Assert.False((await Three(rule, Sample(destination: "10.45.1.20"),
            Sample(destination: "10.46.2.20"), Sample(destination: destination))).Matched);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.1.10")]
    [InlineData("192.0.2.15")]
    [InlineData("10.45.0.20")]
    public async Task NonPublic_Source_Cannot_Trigger(string source)
    {
        Assert.False((await Three(new R552_ExternalNtpMonlistPrivateSubnetFanoutRule(),
            Sample(source, "10.45.1.20"), Sample(source, "10.46.2.20"),
            Sample(source, "192.168.3.20"))).Matched);
    }

    [Fact]
    public async Task Normal_Ntp_Synchronization_Does_Not_Match()
    {
        var a = Sample(destination: "10.45.1.20"); a.ApplicationProtocol = "ntp";
        var b = Sample(destination: "10.46.2.20"); b.ApplicationProtocol = "ntp";
        var c = Sample(destination: "192.168.3.20"); c.ApplicationProtocol = "ntp";
        Assert.False((await Three(new R552_ExternalNtpMonlistPrivateSubnetFanoutRule(), a, b, c)).Matched);
    }

    [Fact]
    public async Task Port_And_Info_Only_Cannot_Spoof_Parsed_Operation()
    {
        var a = Sample(destination: "10.45.1.20"); a.ApplicationProtocol = null; a.Info = "ntp.mode7.monlist token=secret";
        var b = Sample(destination: "10.46.2.20"); b.ApplicationProtocol = null; b.Info = "ntp.mode7.monlist";
        var c = Sample(destination: "192.168.3.20"); c.ApplicationProtocol = null; c.Info = "ntp.mode7.monlist";
        Assert.False((await Three(new R552_ExternalNtpMonlistPrivateSubnetFanoutRule(), a, b, c)).Matched);
    }

    [Fact]
    public async Task Repeated_Same_Destination_Does_Not_Count_As_Fanout()
    {
        var result = await Three(new R552_ExternalNtpMonlistPrivateSubnetFanoutRule(),
            Sample(), Sample(), Sample());
        Assert.False(result.Matched);
    }

    [Fact]
    public async Task Wrong_Transport_Direction_Or_Port_Fails_Closed()
    {
        var rule = new R552_ExternalNtpMonlistPrivateSubnetFanoutRule();
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
        var rule = new R552_ExternalNtpMonlistPrivateSubnetFanoutRule();
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
        var rule = new R552_ExternalNtpMonlistPrivateSubnetFanoutRule();
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
        var rule = new R552_ExternalNtpMonlistPrivateSubnetFanoutRule();
        var first = Sample(destination: "10.45.1.20");
        var second = Sample(destination: "10.46.2.20"); second.Id = first.Id;
        Assert.False((await rule.EvaluateAsync(At(first))).Matched);
        Assert.False((await rule.EvaluateAsync(At(second, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "192.168.3.20"), 2))).Matched);
    }

    [Fact]
    public async Task Out_Of_Order_Observation_Cannot_Complete_Fanout()
    {
        var rule = new R552_ExternalNtpMonlistPrivateSubnetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.45.1.20"), 30))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.46.2.20"), 10))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "192.168.3.20"), 31))).Matched);
    }

    [Fact]
    public async Task Separate_Sources_Do_Not_Share_Distinct_Target_Counts()
    {
        var rule = new R552_ExternalNtpMonlistPrivateSubnetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Sample("8.8.8.8", "10.45.1.20")))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample("1.1.1.1", "10.46.2.20"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample("8.8.8.8", "192.168.3.20"), 2))).Matched);
    }

    [Fact]
    public async Task Expired_Window_Does_Not_Recycle_Old_Targets()
    {
        var rule = new R552_ExternalNtpMonlistPrivateSubnetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.45.1.20")))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.46.2.20"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "192.168.3.20"), 302))).Matched);
    }

    [Fact]
    public async Task Cooldown_Returns_Suppressed_Match_Without_Second_Event()
    {
        var rule = new R552_ExternalNtpMonlistPrivateSubnetFanoutRule();
        Assert.True((await Three(rule, Sample(destination: "10.45.1.20"),
            Sample(destination: "10.46.2.20"), Sample(destination: "192.168.3.20"))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.45.1.20"), 303))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.46.2.20"), 304))).Matched);
        var result = await rule.EvaluateAsync(At(Sample(destination: "192.168.3.20"), 305));
        Assert.True(result.Suppressed);
        Assert.Empty(result.Events);
    }

    [Fact]
    public async Task Raw_Info_And_Sensitive_Strings_Never_Enter_Event()
    {
        var a = Sample(destination: "10.45.1.20"); a.Info = "password=secret-marker";
        var b = Sample(destination: "10.46.2.20"); b.Info = "token=secret-marker";
        var c = Sample(destination: "192.168.3.20"); c.Info = "secret-marker";
        var result = await Three(new R552_ExternalNtpMonlistPrivateSubnetFanoutRule(), a, b, c);
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains("secret-marker", StringComparison.Ordinal));
    }


    [Fact]
    public async Task Distinct_Hosts_In_One_Private_Subnet_Do_Not_Inflate_Count()
    {
        var rule = new R552_ExternalNtpMonlistPrivateSubnetFanoutRule();
        Assert.False((await Three(rule,
            Sample(destination: "10.45.1.20"),
            Sample(destination: "10.45.1.21"),
            Sample(destination: "10.46.2.20"))).Matched);
    }

    [Fact]
    public async Task Concurrent_Distinct_Private_Subnets_Produce_At_Most_One_Match()
    {
        var rule = new R552_ExternalNtpMonlistPrivateSubnetFanoutRule();
        var results = await Task.WhenAll(
            rule.EvaluateAsync(At(Sample(destination: "10.45.1.20"))).AsTask(),
            rule.EvaluateAsync(At(Sample(destination: "10.46.2.20"))).AsTask(),
            rule.EvaluateAsync(At(Sample(destination: "192.168.3.20"))).AsTask());
        Assert.Equal(1, results.Count(result => result.Matched));
    }

    [Fact]
    public async Task PacketHandler_Real_Udp_Producer_Supports_Private_Subnet_Positive()
    {
        static TrafficRecord Parsed(string source, string target)
        {
            byte[] payload = { 0x27, 0x00, 0x03, 0x2a, 0, 0, 0, 0 };
            var frame = new byte[20 + 8 + payload.Length];
            frame[0] = 0x45;
            frame[2] = (byte)(frame.Length >> 8);
            frame[3] = (byte)frame.Length;
            frame[8] = 64;
            frame[9] = 17;
            IPAddress.Parse(source).GetAddressBytes().CopyTo(frame, 12);
            IPAddress.Parse(target).GetAddressBytes().CopyTo(frame, 16);
            frame[20] = 0x9c;
            frame[21] = 0x40; // UDP source 40000.
            frame[22] = 0x00;
            frame[23] = 0x7b; // UDP destination 123.
            frame[24] = 0;
            frame[25] = 16;
            payload.CopyTo(frame, 28);
            var record = new PacketHandler().ParseFrame(frame, (LinkLayers)12);
            Assert.NotNull(record);
            return record!;
        }

        var rule = new R552_ExternalNtpMonlistPrivateSubnetFanoutRule();
        var first = Parsed("8.8.8.8", "10.45.1.20");
        var second = Parsed("8.8.8.8", "10.46.2.20");
        var third = Parsed("8.8.8.8", "192.168.3.20");
        Assert.All(new[] { first, second, third }, record =>
        {
            Assert.Equal("ntp.mode7.monlist", record.ApplicationProtocol);
            Assert.Equal(4, record.IpVersion);
            Assert.True(record.IsUdp);
            Assert.Equal(8, record.L4Len);
        });
        var result = await Three(rule, first, second, third);
        Assert.True(result.Matched);
        Assert.Equal("R552", Assert.Single(result.Events).RuleId);
    }

    [Fact]
    public void Unique_Registry_Entry_Has_Candidate_Shadow_Policy()
    {
        var rule = new R552_ExternalNtpMonlistPrivateSubnetFanoutRule();
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(84, rule.PrecisionProfile.MinimumConfidence);
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Single(RuleRegistry.CreateDefaultRules().Where(r => r.Descriptor.RuleId == "R552"));
        Assert.True(RulePrecisionCatalog.Validate("R552", Sample()).CanEvaluate);
    }
}
