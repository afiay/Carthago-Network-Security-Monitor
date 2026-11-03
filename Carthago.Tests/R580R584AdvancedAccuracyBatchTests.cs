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
using Xunit;

namespace Carthago.Tests;

public sealed class R580R584AdvancedAccuracyBatchTests
{
    private static readonly DateTime Origin = new(2026, 11, 3, 1, 0, 0, DateTimeKind.Utc);
    private static readonly string[] Ids = { "R580", "R581", "R582", "R583", "R584" };

    private static IDetectionRule Rule(string id) => id switch
    {
        "R580" => new R580_ExternalRedisConfigRequestSubnetFanoutRule(),
        "R581" => new R581_OutboundRedisConfigRequestSubnetFanoutRule(),
        "R582" => new R582_OutboundDefaultBasicAdminSubnetFanoutRule(),
        "R583" => new R583_OutboundBacnetWhoIsSubnetFanoutRule(),
        "R584" => new R584_OutboundSmb2WriteSubnetFanoutRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static string Source(string id) => id == "R580" ? "8.8.8.8" : "10.1.1.20";
    private static string[] Targets(string id) => id == "R580"
        ? new[] { "10.2.1.10", "10.3.1.10", "10.4.1.10",
                  "10.5.1.10", "10.6.1.10", "10.7.1.10" }
        : new[] { "8.8.8.8", "9.9.9.9", "1.1.1.1",
                  "4.4.4.4", "5.5.5.5", "6.6.6.6" };

    private static TrafficRecord Sample(string id, string? source = null, string? destination = null)
    {
        var record = new TrafficRecord
        {
            Id = Guid.NewGuid(),
            Source = source ?? Source(id),
            Destination = destination ?? Targets(id)[0],
            IpVersion = 4, Protocol = "TCP", IsTcp = true, IsUdp = false,
            SourcePort = 41001, DestinationPort = 6379,
            L4Len = 64, Length = 200,
            ApplicationProtocol = "redis.resp2",
            RedisRespConfigSetRequestObserved = true
        };
        switch (id)
        {
            case "R580":
            case "R581":
                break;
            case "R582":
                record.ApplicationProtocol = "HTTP";
                record.DestinationPort = 80;
                record.L4Len = 120;
                record.RedisRespConfigSetRequestObserved = false;
                record.HttpBasicDefaultCredentialObserved = true;
                record.HttpMethod = "GET";
                record.HttpUri = "/admin";
                record.HttpHost = "gateway.lab.internal";
                record.HttpRequestHeaders = "Authorization: [REDACTED]";
                break;
            case "R583":
                record.Protocol = "UDP"; record.IsTcp = false; record.IsUdp = true;
                record.SourcePort = 47808; record.DestinationPort = 47808;
                record.L4Len = 8; record.ApplicationProtocol = "bacnet.whois";
                record.ApplicationService = "BACnet";
                record.RedisRespConfigSetRequestObserved = false;
                break;
            case "R584":
                record.DestinationPort = 445;
                record.L4Len = 117; record.ApplicationProtocol = "smb2.write.request";
                record.RedisRespConfigSetRequestObserved = false;
                break;
        }
        return record;
    }

    private static RuleEvaluationContext At(TrafficRecord r, int offset = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(offset));

    private static async Task<RuleEvaluationResult> Three(
        string id, IDetectionRule? rule = null, string? source = null, int start = 0)
    {
        rule ??= Rule(id);
        var targets = Targets(id);
        Assert.False((await rule.EvaluateAsync(At(Sample(id, source, targets[0]), start))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(id, source, targets[1]), start + 1))).Matched);
        return await rule.EvaluateAsync(At(Sample(id, source, targets[2]), start + 2));
    }

    [Theory]
    [InlineData("R580")][InlineData("R581")][InlineData("R582")]
    [InlineData("R583")][InlineData("R584")]
    public async Task Three_Distinct_Parsed_Request_Subnets_Trigger_Only_One_Candidate(string id)
    {
        var result = await Three(id);
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal(id, evt.RuleId);
        Assert.Equal(3, evt.Count);
        Assert.Equal(300, evt.WindowSeconds);
        Assert.DoesNotContain("password", evt.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("R580")][InlineData("R581")][InlineData("R582")]
    [InlineData("R583")][InlineData("R584")]
    public async Task Repeated_Hosts_On_Same_24_Do_Not_Reach_Threshold(string id)
    {
        var targets = Targets(id);
        var same24 = targets[0].Substring(0, targets[0].LastIndexOf('.') + 1);
        var rule = Rule(id);
        for (var n = 10; n < 13; n++)
            Assert.False((await rule.EvaluateAsync(At(Sample(id, destination: same24 + n), n))).Matched);
    }

    [Theory]
    [InlineData("R580")][InlineData("R581")][InlineData("R582")]
    [InlineData("R583")][InlineData("R584")]
    public async Task One_Or_Two_Subnets_And_Mixed_Sources_Never_Combine(string id)
    {
        var rule = Rule(id);
        var destinations = Targets(id);
        Assert.False((await rule.EvaluateAsync(At(Sample(id, destination: destinations[0])))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(id, destination: destinations[1]), 1))).Matched);
        var other = id == "R580" ? "9.9.9.9" : "10.2.2.20";
        Assert.False((await rule.EvaluateAsync(At(Sample(id, other, destinations[2]), 2))).Matched);
    }

    [Theory]
    [InlineData("R580")][InlineData("R581")][InlineData("R582")]
    [InlineData("R583")][InlineData("R584")]
    public async Task Duplicate_Ids_Cannot_Make_Three_Subnets(string id)
    {
        var rule = Rule(id);
        var destinations = Targets(id);
        var first = Sample(id, destination: destinations[0]);
        var duplicate = Sample(id, destination: destinations[1]); duplicate.Id = first.Id;
        Assert.False((await rule.EvaluateAsync(At(first))).Matched);
        Assert.False((await rule.EvaluateAsync(At(duplicate, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(id, destination: destinations[2]), 2))).Matched);
    }

    [Theory]
    [InlineData("R580")][InlineData("R581")][InlineData("R582")]
    [InlineData("R583")][InlineData("R584")]
    public async Task Out_Of_Order_And_Expired_Packets_Do_Not_Count(string id)
    {
        var rule = Rule(id);
        var dest = Targets(id);
        Assert.False((await rule.EvaluateAsync(At(Sample(id, destination: dest[0]), 10))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(id, destination: dest[1]), 9))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(id, destination: dest[2]), 311))).Matched);
    }

    [Theory]
    [InlineData("R580")][InlineData("R581")][InlineData("R582")]
    [InlineData("R583")][InlineData("R584")]
    public async Task Wrong_Network_Boundary_And_Special_Addresses_Fail_Closed(string id)
    {
        var rule = Rule(id);
        var wrongSource = id == "R580" ? "10.1.1.20" : "8.8.8.8";
        Assert.False((await rule.EvaluateAsync(At(Sample(id, wrongSource)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(id, destination: "192.0.2.10"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(id, destination: "100.64.2.10"), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(id, destination: "224.0.0.1"), 3))).Matched);
    }

    [Theory]
    [InlineData("R580")][InlineData("R581")][InlineData("R582")]
    [InlineData("R583")][InlineData("R584")]
    public async Task Port_Only_Info_Only_And_Contradictory_Transport_Fail_Closed(string id)
    {
        var rule = Rule(id);
        var unclassified = Sample(id); unclassified.ApplicationProtocol = null;
        unclassified.RedisRespConfigSetRequestObserved = false;
        unclassified.HttpBasicDefaultCredentialObserved = false;
        unclassified.Info = "CONFIG SET /admin bacnet.whois smb2.write.request";
        var tls = Sample(id); tls.TlsVersion = "TLS1.3";
        var dns = Sample(id); dns.DnsQname = "forged.example";
        var quic = Sample(id); quic.IsQuic = true;
        var wrong = Sample(id); wrong.DestinationPort = 443;
        Assert.False((await rule.EvaluateAsync(At(unclassified))).Matched);
        Assert.False((await rule.EvaluateAsync(At(tls, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(dns, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(quic, 3))).Matched);
        Assert.False((await rule.EvaluateAsync(At(wrong, 4))).Matched);
    }

    [Theory]
    [InlineData("R580")][InlineData("R581")][InlineData("R582")]
    [InlineData("R583")][InlineData("R584")]
    public async Task Malformed_Metadata_And_Ordinary_Operations_Are_Negatives(string id)
    {
        var rule = Rule(id);
        var empty = Sample(id); empty.Id = Guid.Empty;
        var shortFrame = Sample(id); shortFrame.Length = 1;
        var ipv6 = Sample(id); ipv6.IpVersion = 6;
        var ordinary = Sample(id);
        switch (id)
        {
            case "R580":
            case "R581": ordinary.RedisRespConfigSetRequestObserved = false; break;
            case "R582": ordinary.HttpBasicDefaultCredentialObserved = false; break;
            case "R583": ordinary.ApplicationProtocol = "bacnet.iam"; break;
            case "R584": ordinary.ApplicationProtocol = "smb2.create.request"; break;
        }
        Assert.False((await rule.EvaluateAsync(At(empty))).Matched);
        Assert.False((await rule.EvaluateAsync(At(shortFrame, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(ipv6, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(ordinary, 3))).Matched);
    }

    [Theory]
    [InlineData("R580")][InlineData("R581")][InlineData("R582")]
    [InlineData("R583")][InlineData("R584")]
    public async Task Fresh_Second_Fanout_Within_Cooldown_Is_Suppressed(string id)
    {
        var rule = Rule(id);
        Assert.True((await Three(id, rule)).Matched);
        var dest = Targets(id);
        for (var i = 3; i < 5; i++)
            Assert.False((await rule.EvaluateAsync(At(Sample(id, destination: dest[i]), i))).Matched);
        var result = await rule.EvaluateAsync(At(Sample(id, destination: dest[5]), 5));
        Assert.True(result.Suppressed);
        Assert.Empty(result.Events);
    }

    [Theory]
    [InlineData("R580")][InlineData("R581")][InlineData("R582")]
    [InlineData("R583")][InlineData("R584")]
    public async Task Freeform_Info_Marker_Is_Not_Persisted_In_Event_Evidence(string id)
    {
        var rule = Rule(id);
        var targets = Targets(id);
        Assert.False((await rule.EvaluateAsync(At(Sample(id, destination: targets[0])))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(id, destination: targets[1]), 1))).Matched);
        var last = Sample(id, destination: targets[2]);
        last.Info = "untrusted-diagnostic-secret-marker";
        var evt = Assert.Single((await rule.EvaluateAsync(At(last, 2))).Events);
        Assert.DoesNotContain("untrusted-diagnostic-secret-marker", evt.Evidence);
        Assert.DoesNotContain("untrusted-diagnostic-secret-marker", evt.Description);
        Assert.Contains(evt.StructuredEvidence!.Items, item =>
            item.Key.EndsWith(".outcome", StringComparison.Ordinal) &&
            item.Value == "request_only_unknown");
    }

    [Fact]
    public void Redis_Producer_Only_Classifies_A_Complete_Request_After_Handshake()
    {
        static byte[] TcpFrame(string source, string destination, int sp, int dp,
            uint sequence, byte flags, byte[] payload)
        {
            var frame = new byte[40 + payload.Length];
            frame[0] = 0x45;
            frame[2] = (byte)(frame.Length >> 8);
            frame[3] = (byte)frame.Length;
            frame[8] = 64; frame[9] = 6;
            IPAddress.Parse(source).GetAddressBytes().CopyTo(frame, 12);
            IPAddress.Parse(destination).GetAddressBytes().CopyTo(frame, 16);
            frame[20] = (byte)(sp >> 8); frame[21] = (byte)sp;
            frame[22] = (byte)(dp >> 8); frame[23] = (byte)dp;
            frame[24] = (byte)(sequence >> 24); frame[25] = (byte)(sequence >> 16);
            frame[26] = (byte)(sequence >> 8); frame[27] = (byte)sequence;
            frame[32] = 0x50; frame[33] = flags;
            payload.CopyTo(frame, 40);
            return frame;
        }
        static byte[] Command(string name) => Encoding.ASCII.GetBytes(
            name == "CONFIG"
                ? "*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$7\r\ntimeout\r\n$2\r\n30\r\n"
                : "*1\r\n$4\r\nPING\r\n");

        static TrafficRecord Packet(string name)
        {
            var handler = new PacketHandler();
            var link = (PacketDotNet.LinkLayers)12;
            Assert.NotNull(handler.ParseFrame(TcpFrame("8.8.8.8", "10.2.1.10",
                41001, 6379, 0, 0x02, Array.Empty<byte>()), link));
            Assert.NotNull(handler.ParseFrame(TcpFrame("10.2.1.10", "8.8.8.8",
                6379, 41001, 100, 0x12, Array.Empty<byte>()), link));
            return Assert.IsType<TrafficRecord>(handler.ParseFrame(
                TcpFrame("8.8.8.8", "10.2.1.10", 41001, 6379, 1, 0x18, Command(name)), link));
        }
        Assert.True(Packet("CONFIG").RedisRespConfigSetRequestObserved);
        Assert.False(Packet("PING").RedisRespConfigSetRequestObserved);
    }

    [Fact]
    public void Registration_Is_Sequential_Unique_Candidate_And_Shadow()
    {
        var catalog = RuleRegistry.CreateDefaultRules();
        foreach (var id in Ids)
        {
            var rule = Assert.Single(catalog.Where(r => r.Descriptor.RuleId == id));
            var precision = Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(rule);
            Assert.Equal(RulePrecisionMaturity.Candidate, precision.PrecisionProfile.Maturity);
            Assert.Equal(RuleRuntimeMode.Shadow, precision.PrecisionProfile.DefaultMode);
        }
        Assert.Equal(Ids.Length, catalog.Count(r => Ids.Contains(r.Descriptor.RuleId)));
    }

    [Fact]
    public void Existing_Producers_Identify_Operations_Without_Plaintext_Evidence_Retention()
    {
        byte[] whoIs = { 0x81, 0x0a, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08 };
        Assert.True(OtProtocolLight.TryIdentifyUdp(whoIs, 47808, 47808, out var bacnet));
        Assert.Equal("bacnet.whois", bacnet);
        var smb = new byte[117];
        smb[3] = 113; smb[4] = 0xfe; smb[5] = 0x53; smb[6] = 0x4d; smb[7] = 0x42;
        smb[8] = 64; smb[16] = 9; smb[68] = 49; smb[70] = 112; smb[72] = 1;
        Assert.True(NetworkBatch246250Wire.Smb2Write(smb, 41001, 445));
        Assert.False(NetworkBatch246250Wire.Smb2Write(smb, 445, 41001));
        var req = Encoding.ASCII.GetBytes("GET /admin HTTP/1.1\r\nHost: gateway.lab.internal\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n");
        Assert.True(HttpLight.TryParseHttp(req, out var parsed));
        Assert.True(parsed.ObservedDefaultBasicCredential);
        Assert.DoesNotContain("YWRtaW46YWRtaW4=", parsed.JoinedHeaderLines);
    }
}
