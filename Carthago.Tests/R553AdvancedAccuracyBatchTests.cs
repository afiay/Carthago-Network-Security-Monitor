// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed.
using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using SharpPcap;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public sealed class R553AdvancedAccuracyBatchTests
{
    private static readonly DateTime Origin = new(2026, 11, 2, 4, 0, 0, DateTimeKind.Utc);

    private static TrafficRecord Sample(string source = "10.90.1.10", string destination = "10.91.1.20")
        => new()
        {
            Id = Guid.NewGuid(), Source = source, Destination = destination,
            Protocol = "TCP", IsTcp = true, IsUdp = false, IpVersion = 4,
            SourcePort = 40000, DestinationPort = 445,
            ApplicationProtocol = "smb2.write.request",
            Length = 157, L4Len = 117, Info = string.Empty
        };

    private static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    private static async Task<RuleEvaluationResult> Three(
        R553_CrossSubnetSmb2WriteRequestFanoutRule rule,
        TrafficRecord a, TrafficRecord b, TrafficRecord c)
    {
        Assert.False((await rule.EvaluateAsync(At(a))).Matched);
        Assert.False((await rule.EvaluateAsync(At(b, 1))).Matched);
        return await rule.EvaluateAsync(At(c, 2));
    }

    private static byte[] SmbWrite()
    {
        // Publicly reproducible minimal SMB2 WRITE-shaped fixture:
        // RFC1002 4-byte length + 64-byte SMB2 header + 49-byte WRITE structure.
        var p = new byte[117];
        p[3] = 113;
        p[4] = 0xfe; p[5] = 0x53; p[6] = 0x4d; p[7] = 0x42;
        p[8] = 64; p[16] = 9; p[68] = 49; p[70] = 112; p[72] = 1;
        return p;
    }

    [Fact]
    public void Bounded_Smb2_Write_Wire_Classifier_Recognizes_Request()
        => Assert.True(NetworkBatch246250Wire.Smb2Write(SmbWrite(), 40000, 445));

    [Fact]
    public void Create_Response_Truncation_And_Port_Only_Do_Not_Claim_Write()
    {
        var create = SmbWrite(); create[16] = 5;
        var response = SmbWrite(); response[20] = 1;
        var shortFrame = SmbWrite()[..116];
        Assert.False(NetworkBatch246250Wire.Smb2Write(create, 40000, 445));
        Assert.False(NetworkBatch246250Wire.Smb2Write(response, 40000, 445));
        Assert.False(NetworkBatch246250Wire.Smb2Write(shortFrame, 40000, 445));
        Assert.False(NetworkBatch246250Wire.Smb2Write(SmbWrite(), 445, 40000));
    }

    [Fact]
    public async Task Three_Distinct_Remote_Private_Subnets_Match()
    {
        var result = await Three(new R553_CrossSubnetSmb2WriteRequestFanoutRule(),
            Sample(destination: "10.91.1.20"), Sample(destination: "10.92.2.20"),
            Sample(destination: "192.168.3.20"));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R553", evt.RuleId);
        Assert.Equal(3, evt.Count);
        Assert.Equal(300, evt.WindowSeconds);
        Assert.Equal(SeverityLevel.High, evt.Severity);
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("192.0.2.4")]
    [InlineData("198.51.100.9")]
    [InlineData("169.254.1.1")]
    [InlineData("127.0.0.1")]
    public async Task NonPrivate_Third_Target_Does_Not_Complete_Fanout(string destination)
    {
        Assert.False((await Three(new R553_CrossSubnetSmb2WriteRequestFanoutRule(),
            Sample(destination: "10.91.1.20"), Sample(destination: "10.92.2.20"),
            Sample(destination: destination))).Matched);
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("192.0.2.4")]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.1.1")]
    public async Task NonPrivate_Source_Does_Not_Complete_Fanout(string source)
    {
        Assert.False((await Three(new R553_CrossSubnetSmb2WriteRequestFanoutRule(),
            Sample(source, "10.91.1.20"), Sample(source, "10.92.2.20"),
            Sample(source, "192.168.3.20"))).Matched);
    }

    [Fact]
    public async Task Three_Hosts_In_One_Private_Subnet_Do_Not_Inflate_Count()
    {
        Assert.False((await Three(new R553_CrossSubnetSmb2WriteRequestFanoutRule(),
            Sample(destination: "10.91.1.20"), Sample(destination: "10.91.1.21"),
            Sample(destination: "10.91.1.22"))).Matched);
    }

    [Fact]
    public async Task Same_Source_Subnet_Is_Not_Remote_Fanout()
    {
        Assert.False((await Three(new R553_CrossSubnetSmb2WriteRequestFanoutRule(),
            Sample(destination: "10.90.1.20"), Sample(destination: "10.90.1.21"),
            Sample(destination: "10.90.1.22"))).Matched);
    }

    [Fact]
    public async Task Generic_Smb_And_Info_Only_Spoofing_Fail_Closed()
    {
        var a = Sample(destination: "10.91.1.20"); a.ApplicationProtocol = null; a.Info = "smb2.write.request password=marker";
        var b = Sample(destination: "10.92.2.20"); b.ApplicationProtocol = "SMB";
        var c = Sample(destination: "192.168.3.20"); c.ApplicationProtocol = "smb2.create.request";
        Assert.False((await Three(new R553_CrossSubnetSmb2WriteRequestFanoutRule(), a, b, c)).Matched);
    }

    [Fact]
    public async Task Wrong_Transport_Direction_And_Port_Fail_Closed()
    {
        var rule = new R553_CrossSubnetSmb2WriteRequestFanoutRule();
        var udp = Sample(); udp.IsTcp = false; udp.IsUdp = true; udp.Protocol = "UDP";
        var response = Sample(); response.SourcePort = 445; response.DestinationPort = 40000;
        var wrongPort = Sample(); wrongPort.DestinationPort = 1445;
        Assert.False((await rule.EvaluateAsync(At(udp))).Matched);
        Assert.False((await rule.EvaluateAsync(At(response, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(wrongPort, 2))).Matched);
    }

    [Fact]
    public async Task Contradictory_Http_Dns_Tls_And_Encrypted_Metadata_Fail_Closed()
    {
        var rule = new R553_CrossSubnetSmb2WriteRequestFanoutRule();
        var tls = Sample(); tls.TlsVersion = "TLS1.3";
        var http = Sample(); http.HttpUri = "/admin";
        var dns = Sample(); dns.DnsQname = "example.test";
        var quic = Sample(); quic.IsQuic = true;
        Assert.False((await rule.EvaluateAsync(At(tls))).Matched);
        Assert.False((await rule.EvaluateAsync(At(http, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(dns, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(quic, 3))).Matched);
    }

    [Fact]
    public async Task Invalid_Id_Length_And_IpVersion_Fail_Closed()
    {
        var rule = new R553_CrossSubnetSmb2WriteRequestFanoutRule();
        var empty = Sample(); empty.Id = Guid.Empty;
        var shortFrame = Sample(); shortFrame.L4Len = 116;
        var overlong = Sample(); overlong.L4Len = 4097;
        var inconsistent = Sample(); inconsistent.Length = 120;
        var ipv6 = Sample(); ipv6.IpVersion = 6;
        Assert.False((await rule.EvaluateAsync(At(empty))).Matched);
        Assert.False((await rule.EvaluateAsync(At(shortFrame, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(overlong, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(inconsistent, 3))).Matched);
        Assert.False((await rule.EvaluateAsync(At(ipv6, 4))).Matched);
    }

    [Fact]
    public async Task Duplicate_Packet_Id_Cannot_Complete_Three_Subnets()
    {
        var rule = new R553_CrossSubnetSmb2WriteRequestFanoutRule();
        var a = Sample(destination: "10.91.1.20");
        var b = Sample(destination: "10.92.2.20"); b.Id = a.Id;
        Assert.False((await rule.EvaluateAsync(At(a))).Matched);
        Assert.False((await rule.EvaluateAsync(At(b, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "192.168.3.20"), 2))).Matched);
    }

    [Fact]
    public async Task Out_Of_Order_Observation_Cannot_Complete_Fanout()
    {
        var rule = new R553_CrossSubnetSmb2WriteRequestFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.91.1.20"), 30))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.92.2.20"), 10))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "192.168.3.20"), 31))).Matched);
    }

    [Fact]
    public async Task Separate_Sources_Do_Not_Share_Target_Count()
    {
        var rule = new R553_CrossSubnetSmb2WriteRequestFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Sample("10.90.1.10", "10.91.1.20")))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample("10.90.1.11", "10.92.2.20"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample("10.90.1.10", "192.168.3.20"), 2))).Matched);
    }

    [Fact]
    public async Task Expired_Window_Does_Not_Count_Stale_Subnets()
    {
        var rule = new R553_CrossSubnetSmb2WriteRequestFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.91.1.20")))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.92.2.20"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "192.168.3.20"), 302))).Matched);
    }

    [Fact]
    public async Task Cooldown_Suppresses_Second_Three_Subnet_Correlation()
    {
        var rule = new R553_CrossSubnetSmb2WriteRequestFanoutRule();
        Assert.True((await Three(rule, Sample(destination: "10.91.1.20"),
            Sample(destination: "10.92.2.20"), Sample(destination: "192.168.3.20"))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.91.1.20"), 303))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.92.2.20"), 304))).Matched);
        var result = await rule.EvaluateAsync(At(Sample(destination: "192.168.3.20"), 305));
        Assert.True(result.Suppressed);
        Assert.Empty(result.Events);
    }

    [Fact]
    public async Task Concurrent_Third_Targets_Emit_At_Most_One_Match()
    {
        var rule = new R553_CrossSubnetSmb2WriteRequestFanoutRule();
        var results = await Task.WhenAll(
            rule.EvaluateAsync(At(Sample(destination: "10.91.1.20"))).AsTask(),
            rule.EvaluateAsync(At(Sample(destination: "10.92.2.20"))).AsTask(),
            rule.EvaluateAsync(At(Sample(destination: "192.168.3.20"))).AsTask());
        Assert.Equal(1, results.Count(r => r.Matched));
    }

    [Fact]
    public async Task Raw_Info_And_Sensitive_Paths_Are_Not_Copied_To_Evidence()
    {
        var a = Sample(destination: "10.91.1.20"); a.Info = "password=secret-marker";
        var b = Sample(destination: "10.92.2.20"); b.Info = "share=secret-marker";
        var c = Sample(destination: "192.168.3.20"); c.Info = "secret-marker";
        var result = await Three(new R553_CrossSubnetSmb2WriteRequestFanoutRule(), a, b, c);
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains("secret-marker", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Actual_PacketHandler_Producer_Recognizes_Smb2_Write_Shape()
    {
        static TrafficRecord Parsed(string source, string destination)
        {
            var payload = SmbWrite();
            var frame = new byte[20 + 20 + payload.Length];
            frame[0] = 0x45;
            frame[2] = (byte)(frame.Length >> 8);
            frame[3] = (byte)frame.Length;
            frame[8] = 64; frame[9] = 6;
            IPAddress.Parse(source).GetAddressBytes().CopyTo(frame, 12);
            IPAddress.Parse(destination).GetAddressBytes().CopyTo(frame, 16);
            frame[20] = 0x9c; frame[21] = 0x40; // TCP source 40000
            frame[22] = 0x01; frame[23] = 0xbd; // TCP destination 445
            frame[32] = 0x50; frame[33] = 0x18; // TCP data offset 20, PSH/ACK
            payload.CopyTo(frame, 40);
            var record = new PacketHandler().ParseFrame(frame, (PacketDotNet.LinkLayers)12);
            Assert.NotNull(record);
            return record!;
        }

        var a = Parsed("10.90.1.10", "10.91.1.20");
        var b = Parsed("10.90.1.10", "10.92.2.20");
        var c = Parsed("10.90.1.10", "192.168.3.20");
        Assert.All(new[] { a, b, c }, record =>
        {
            Assert.Equal("smb2.write.request", record.ApplicationProtocol);
            Assert.Equal(117, record.L4Len);
            Assert.True(record.IsTcp);
        });
        var result = await Three(new R553_CrossSubnetSmb2WriteRequestFanoutRule(), a, b, c);
        Assert.True(result.Matched);
    }

    [Fact]
    public void Unique_Registry_Entry_Has_Candidate_Shadow_Policy()
    {
        var rule = new R553_CrossSubnetSmb2WriteRequestFanoutRule();
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(88, rule.PrecisionProfile.MinimumConfidence);
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Single(RuleRegistry.CreateDefaultRules().Where(r => r.Descriptor.RuleId == "R553"));
        // The parser-labelled record does not preserve raw payload bytes.
        // Central precision validation must not treat ApplicationProtocol alone
        // as proof of the independent Payload telemetry requirement.
        var validation = RulePrecisionCatalog.Validate("R553", Sample());
        Assert.False(validation.CanEvaluate);
        Assert.Contains("Payload", validation.MissingTelemetry);
    }
}
