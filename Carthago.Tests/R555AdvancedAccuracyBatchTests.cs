// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed.
using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using SharpPcap;
using Xunit;

namespace Carthago.Tests;

public sealed class R555AdvancedAccuracyBatchTests
{
    private static readonly DateTime Origin = new(2026, 11, 2, 5, 0, 0, DateTimeKind.Utc);

    private static TrafficRecord Upload(string source = "10.90.1.10",
        string destination = "8.8.8.8", string operation = "ftp.stor")
        => new()
        {
            Id = Guid.NewGuid(), Source = source, Destination = destination,
            Protocol = "TCP", IsTcp = true, IpVersion = 4,
            SourcePort = 40000, DestinationPort = 21,
            ApplicationProtocol = operation, L4Len = 17, Length = 57, Info = string.Empty
        };

    private static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    private static async Task<RuleEvaluationResult> Three(
        R555_ExternalFtpUploadCommandSubnetFanoutRule rule,
        TrafficRecord a, TrafficRecord b, TrafficRecord c,
        int first = 0, int second = 1, int third = 2)
    {
        Assert.False((await rule.EvaluateAsync(At(a, first))).Matched);
        Assert.False((await rule.EvaluateAsync(At(b, second))).Matched);
        return await rule.EvaluateAsync(At(c, third));
    }

    private static TrafficRecord Parsed(string destination, string command = "STOR report.bin\r\n")
    {
        var payload = Encoding.ASCII.GetBytes(command);
        var frame = new byte[40 + payload.Length];
        frame[0] = 0x45;
        frame[2] = (byte)(frame.Length >> 8);
        frame[3] = (byte)frame.Length;
        frame[8] = 64; frame[9] = 6;
        IPAddress.Parse("10.90.1.10").GetAddressBytes().CopyTo(frame, 12);
        IPAddress.Parse(destination).GetAddressBytes().CopyTo(frame, 16);
        frame[20] = 0x9c; frame[21] = 0x40; // client TCP source port 40000
        frame[22] = 0; frame[23] = 21;
        frame[32] = 0x50; frame[33] = 0x18;
        payload.CopyTo(frame, 40);
        var record = new PacketHandler().ParseFrame(frame, (PacketDotNet.LinkLayers)12);
        Assert.NotNull(record);
        return record!;
    }

    [Fact]
    public void PacketHandler_Produces_Only_Real_Ftp_Upload_Request_Shapes()
    {
        Assert.Equal("ftp.stor", Parsed("8.8.8.8").ApplicationProtocol);
        Assert.Equal("ftp.appe", Parsed("9.9.9.9", "APPE report.bin\r\n").ApplicationProtocol);
        Assert.NotEqual("ftp.stor", Parsed("1.1.1.1", "RETR report.bin\r\n").ApplicationProtocol);
        Assert.False(NetworkBatch246250Wire.FtpUpload(
            Encoding.ASCII.GetBytes("STOR report.bin"), 40000, 21, out _));
    }

    [Fact]
    public async Task Three_Distinct_Public_Subnets_Match_High_Shadow_Candidate()
    {
        var result = await Three(new R555_ExternalFtpUploadCommandSubnetFanoutRule(),
            Upload(), Upload(destination: "9.9.9.9"), Upload(destination: "1.1.1.1"));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R555", evt.RuleId);
        Assert.Equal(SeverityLevel.High, evt.Severity);
        Assert.Equal(3, evt.Count);
        Assert.Equal(300, evt.WindowSeconds);
        Assert.Contains(evt.StructuredEvidence!.Items,
            item => item.Key == "ftp.transfer_status" && item.Value == "request_only_unverified");
    }

    [Fact]
    public async Task Real_Parsed_Packets_Can_Complete_The_Fanout()
    {
        var result = await Three(new R555_ExternalFtpUploadCommandSubnetFanoutRule(),
            Parsed("8.8.8.8"), Parsed("9.9.9.9", "APPE report.bin\r\n"),
            Parsed("1.1.1.1"));
        Assert.True(result.Matched);
    }

    [Fact]
    public async Task Legitimate_One_Or_Two_External_Subnets_Do_Not_Match()
    {
        var rule = new R555_ExternalFtpUploadCommandSubnetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Upload()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Upload(destination: "9.9.9.9"), 1))).Matched);
    }

    [Fact]
    public async Task Three_Destinations_Within_Same_Public_Subnet_Do_Not_Match()
    {
        var result = await Three(new R555_ExternalFtpUploadCommandSubnetFanoutRule(),
            Upload(), Upload(destination: "8.8.8.9"), Upload(destination: "8.8.8.10"));
        Assert.False(result.Matched);
    }

    [Theory]
    [InlineData("192.0.2.9")]
    [InlineData("198.51.100.9")]
    [InlineData("203.0.113.9")]
    [InlineData("10.20.30.40")]
    [InlineData("169.254.1.9")]
    public async Task Reserved_Or_Internal_Third_Destination_Fails_Closed(string destination)
    {
        var result = await Three(new R555_ExternalFtpUploadCommandSubnetFanoutRule(),
            Upload(), Upload(destination: "9.9.9.9"), Upload(destination: destination));
        Assert.False(result.Matched);
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("192.0.2.8")]
    [InlineData("127.0.0.1")]
    public async Task NonPrivate_Source_Does_Not_Accumulate_Fanout(string source)
    {
        var result = await Three(new R555_ExternalFtpUploadCommandSubnetFanoutRule(),
            Upload(source: source), Upload(source: source, destination: "9.9.9.9"),
            Upload(source: source, destination: "1.1.1.1"));
        Assert.False(result.Matched);
    }

    [Theory]
    [InlineData("ftp.retr")]
    [InlineData("ftp.list")]
    [InlineData("FTP")]
    public async Task NonUpload_Command_Cannot_Complete_Fanout(string operation)
    {
        var result = await Three(new R555_ExternalFtpUploadCommandSubnetFanoutRule(),
            Upload(), Upload(destination: "9.9.9.9"),
            Upload(destination: "1.1.1.1", operation: operation));
        Assert.False(result.Matched);
    }

    [Fact]
    public async Task Info_Only_And_Port_Only_Claims_Are_Not_Positive_Evidence()
    {
        var a = Upload(); a.ApplicationProtocol = null; a.Info = "STOR password=marker";
        var b = Upload(destination: "9.9.9.9"); b.ApplicationProtocol = "FTP";
        var result = await Three(new R555_ExternalFtpUploadCommandSubnetFanoutRule(),
            a, b, Upload(destination: "1.1.1.1"));
        Assert.False(result.Matched);
    }

    [Fact]
    public async Task Contradictory_Transport_Tls_Http_And_Dns_Fail_Closed()
    {
        var rule = new R555_ExternalFtpUploadCommandSubnetFanoutRule();
        var udp = Upload(); udp.IsTcp = false; udp.IsUdp = true; udp.Protocol = "UDP";
        var tls = Upload(); tls.TlsVersion = "TLS1.3";
        var http = Upload(); http.HttpUri = "/upload";
        var dns = Upload(); dns.DnsQname = "example.test";
        var quic = Upload(); quic.IsQuic = true;
        Assert.False((await rule.EvaluateAsync(At(udp))).Matched);
        Assert.False((await rule.EvaluateAsync(At(tls, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(http, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(dns, 3))).Matched);
        Assert.False((await rule.EvaluateAsync(At(quic, 4))).Matched);
    }

    [Fact]
    public async Task Invalid_Id_Payload_Length_And_Direction_Fail_Closed()
    {
        var rule = new R555_ExternalFtpUploadCommandSubnetFanoutRule();
        var empty = Upload(); empty.Id = Guid.Empty;
        var shortPayload = Upload(); shortPayload.L4Len = 7;
        var hugePayload = Upload(); hugePayload.L4Len = 257;
        var inconsistent = Upload(); inconsistent.Length = 41;
        var reverse = Upload(); reverse.SourcePort = 21; reverse.DestinationPort = 40000;
        var ipv6 = Upload(); ipv6.IpVersion = 6;
        Assert.False((await rule.EvaluateAsync(At(empty))).Matched);
        Assert.False((await rule.EvaluateAsync(At(shortPayload, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(hugePayload, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(inconsistent, 3))).Matched);
        Assert.False((await rule.EvaluateAsync(At(reverse, 4))).Matched);
        Assert.False((await rule.EvaluateAsync(At(ipv6, 5))).Matched);
    }

    [Fact]
    public async Task Duplicate_Packet_Id_Does_Not_Complete_Three_Targets()
    {
        var rule = new R555_ExternalFtpUploadCommandSubnetFanoutRule();
        var a = Upload();
        var b = Upload(destination: "9.9.9.9"); b.Id = a.Id;
        Assert.False((await rule.EvaluateAsync(At(a))).Matched);
        Assert.False((await rule.EvaluateAsync(At(b, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Upload(destination: "1.1.1.1"), 2))).Matched);
    }

    [Fact]
    public async Task Out_Of_Order_Timestamp_Does_Not_Complete_Three_Targets()
    {
        var rule = new R555_ExternalFtpUploadCommandSubnetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Upload(), 30))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Upload(destination: "9.9.9.9"), 10))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Upload(destination: "1.1.1.1"), 31))).Matched);
    }

    [Fact]
    public async Task Different_Private_Sources_Do_Not_Combine_Targets()
    {
        var rule = new R555_ExternalFtpUploadCommandSubnetFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Upload()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Upload(source: "10.90.1.11", destination: "9.9.9.9"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Upload(destination: "1.1.1.1"), 2))).Matched);
    }

    [Fact]
    public async Task Expired_Five_Minute_Window_Cannot_Complete_Fanout()
    {
        var result = await Three(new R555_ExternalFtpUploadCommandSubnetFanoutRule(),
            Upload(), Upload(destination: "9.9.9.9"),
            Upload(destination: "1.1.1.1"), third: 302);
        Assert.False(result.Matched);
    }

    [Fact]
    public async Task New_Fanout_Inside_Cooldown_Is_Suppressed()
    {
        var rule = new R555_ExternalFtpUploadCommandSubnetFanoutRule();
        Assert.True((await Three(rule, Upload(), Upload(destination: "9.9.9.9"),
            Upload(destination: "1.1.1.1"))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Upload(), 303))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Upload(destination: "9.9.9.9"), 304))).Matched);
        var result = await rule.EvaluateAsync(At(Upload(destination: "1.1.1.1"), 305));
        Assert.True(result.Suppressed);
        Assert.Empty(result.Events);
    }

    [Fact]
    public async Task Consumed_Three_Targets_Require_Three_Fresh_Destinations()
    {
        var rule = new R555_ExternalFtpUploadCommandSubnetFanoutRule();
        Assert.True((await Three(rule, Upload(), Upload(destination: "9.9.9.9"),
            Upload(destination: "1.1.1.1"))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Upload(destination: "4.4.4.4"), 3))).Matched);
    }

    [Fact]
    public async Task Concurrent_Third_Targets_Emit_At_Most_One_Event()
    {
        var rule = new R555_ExternalFtpUploadCommandSubnetFanoutRule();
        var results = await Task.WhenAll(
            rule.EvaluateAsync(At(Upload())).AsTask(),
            rule.EvaluateAsync(At(Upload(destination: "9.9.9.9"))).AsTask(),
            rule.EvaluateAsync(At(Upload(destination: "1.1.1.1"))).AsTask());
        Assert.Equal(1, results.Count(r => r.Matched));
    }

    [Fact]
    public async Task Raw_Info_And_Ftp_Paths_Never_Enter_Event_Evidence()
    {
        var a = Upload(); a.Info = "password=secret-marker";
        var b = Upload(destination: "9.9.9.9"); b.Info = "STOR secret-marker";
        var c = Upload(destination: "1.1.1.1"); c.Info = "secret-marker";
        var result = await Three(new R555_ExternalFtpUploadCommandSubnetFanoutRule(), a, b, c);
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains("secret-marker", StringComparison.Ordinal));
    }

    [Fact]
    public void Registry_And_Candidate_Shadow_Policy_Are_Explicit()
    {
        var rule = new R555_ExternalFtpUploadCommandSubnetFanoutRule();
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(88, rule.PrecisionProfile.MinimumConfidence);
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Single(RuleRegistry.CreateDefaultRules().Where(r => r.Descriptor.RuleId == "R555"));
        Assert.True(RulePrecisionCatalog.Validate("R555", Upload()).CanEvaluate);
    }
}
