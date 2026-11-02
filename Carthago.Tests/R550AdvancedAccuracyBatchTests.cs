// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; authored tests, zero executed.
using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using SharpPcap;
using Xunit;

namespace Carthago.Tests;

public sealed class R550AdvancedAccuracyBatchTests
{
    private static readonly DateTime Origin = new(2026, 11, 2, 1, 0, 0, DateTimeKind.Utc);
    private static readonly byte[] WhoIsBytes = { 0x81, 0x0a, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08 };
    // Synthetic BACnet I-Am shape: BVLC/NPDU/unconfirmed APDU with
    // object-id, max APDU, segmentation and vendor fields (no real asset ID).
    private static readonly byte[] IAmBytes =
    {
        0x81, 0x0a, 0x00, 0x15, 0x01, 0x00, 0x10, 0x00,
        0xc4, 0x02, 0x00, 0x00, 0x01, 0x22, 0x05, 0xc4,
        0x91, 0x03, 0x22, 0x00, 0x0f
    };

    private static TrafficRecord Packet(string source, string destination,
        bool whoIs, byte[]? payload = null, int sourcePort = 47808, int destinationPort = 47808)
    {
        var bytes = payload ?? (whoIs ? WhoIsBytes : IAmBytes);
        var frame = new byte[28 + bytes.Length];
        frame[0] = 0x45;
        frame[2] = (byte)(frame.Length >> 8); frame[3] = (byte)frame.Length;
        frame[8] = 64; frame[9] = 17;
        IPAddress.Parse(source).GetAddressBytes().CopyTo(frame, 12);
        IPAddress.Parse(destination).GetAddressBytes().CopyTo(frame, 16);
        frame[20] = (byte)(sourcePort >> 8); frame[21] = (byte)sourcePort;
        frame[22] = (byte)(destinationPort >> 8); frame[23] = (byte)destinationPort;
        var udpLength = bytes.Length + 8;
        frame[24] = (byte)(udpLength >> 8); frame[25] = (byte)udpLength;
        bytes.CopyTo(frame, 28);
        var record = new PacketHandler().ParseFrame(frame, (LinkLayers)12);
        Assert.NotNull(record);
        return record!;
    }

    private static TrafficRecord Request(string target = "10.45.1.20", string source = "8.8.8.8")
        => Packet(source, target, true);

    private static TrafficRecord Reply(string source = "10.45.1.20", string target = "8.8.8.8")
        => Packet(source, target, false);

    private static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    private static async Task<RuleEvaluationResult> TwoPairs(
        R550_BacnetCrossBoundaryDiscoveryReplyRule rule, string publicIp = "8.8.8.8",
        string first = "10.45.1.20", string second = "10.45.2.20")
    {
        Assert.False((await rule.EvaluateAsync(At(Request(first, publicIp)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(first, publicIp), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Request(second, publicIp), 2))).Matched);
        return await rule.EvaluateAsync(At(Reply(second, publicIp), 3));
    }

    [Fact]
    public void PacketHandler_Produces_Both_Expected_Bounded_Bacnet_Labels()
    {
        var request = Request();
        var response = Reply();
        Assert.Equal("bacnet.whois", request.ApplicationProtocol);
        Assert.Equal("bacnet.iam", response.ApplicationProtocol);
        Assert.Equal(8, request.L4Len);
        Assert.Equal(21, response.L4Len);
        Assert.True(request.IsUdp && response.IsUdp);
    }

    [Fact]
    public async Task Two_Reverse_Direction_Pairs_Produce_High_Shadow_Candidate()
    {
        var result = await TwoPairs(new R550_BacnetCrossBoundaryDiscoveryReplyRule());
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R550", evt.RuleId);
        Assert.Equal(SeverityLevel.High, evt.Severity);
        Assert.Equal(2, evt.Count);
        Assert.Equal(300, evt.WindowSeconds);
    }

    [Fact]
    public async Task Only_Requests_Or_Only_Replies_Do_Not_Claim_Discovery_Exposure()
    {
        var rule = new R550_BacnetCrossBoundaryDiscoveryReplyRule();
        Assert.False((await rule.EvaluateAsync(At(Request()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Request("10.45.2.20"), 1))).Matched);
        Assert.False((await new R550_BacnetCrossBoundaryDiscoveryReplyRule()
            .EvaluateAsync(At(Reply()))).Matched);
    }

    [Fact]
    public async Task Internal_Commissioning_Is_Not_A_Public_Boundary()
    {
        var rule = new R550_BacnetCrossBoundaryDiscoveryReplyRule();
        Assert.False((await rule.EvaluateAsync(At(Packet("10.45.1.8", "10.45.1.20", true)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Packet("10.45.1.20", "10.45.1.8", false), 1))).Matched);
    }

    [Theory]
    [InlineData("192.0.2.9")]
    [InlineData("198.51.100.9")]
    [InlineData("203.0.113.9")]
    [InlineData("198.18.0.9")]
    [InlineData("10.1.1.9")]
    public async Task Nonpublic_Or_TestNet_Source_Cannot_Start_A_Pair(string publicIp)
    {
        var rule = new R550_BacnetCrossBoundaryDiscoveryReplyRule();
        Assert.False((await rule.EvaluateAsync(At(Request(source: publicIp)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(target: publicIp), 1))).Matched);
    }

    [Fact]
    public async Task Unrelated_Public_Peer_Cannot_Complete_Reverse_Pair()
    {
        var rule = new R550_BacnetCrossBoundaryDiscoveryReplyRule();
        Assert.False((await rule.EvaluateAsync(At(Request()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(target: "1.1.1.1"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Request("10.45.2.20"), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply("10.45.2.20"), 3))).Matched);
    }

    [Fact]
    public async Task Truncated_And_Spoofed_Bvlc_Length_Are_Not_Qualified()
    {
        var truncated = Packet("8.8.8.8", "10.45.1.20", true,
            new byte[] { 0x81, 0x0a, 0x00, 0x08, 0x01, 0x00, 0x10 });
        var wrongLength = Packet("8.8.8.8", "10.45.1.20", true,
            new byte[] { 0x81, 0x0a, 0x00, 0x09, 0x01, 0x00, 0x10, 0x08 });
        Assert.NotEqual("bacnet.whois", truncated.ApplicationProtocol);
        Assert.NotEqual("bacnet.whois", wrongLength.ApplicationProtocol);
        var rule = new R550_BacnetCrossBoundaryDiscoveryReplyRule();
        Assert.False((await rule.EvaluateAsync(At(truncated))).Matched);
        Assert.False((await rule.EvaluateAsync(At(wrongLength, 1))).Matched);
    }

    [Fact]
    public async Task Short_IAm_Envelope_Cannot_Claim_A_Device_Reply()
    {
        var shortReply = Packet("10.45.1.20", "8.8.8.8", false,
            new byte[] { 0x81, 0x0a, 0x00, 0x08, 0x01, 0x00, 0x10, 0x00 });
        Assert.Equal("bacnet.iam", shortReply.ApplicationProtocol);
        var rule = new R550_BacnetCrossBoundaryDiscoveryReplyRule();
        Assert.False((await rule.EvaluateAsync(At(Request()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(shortReply, 1))).Matched);
    }

    [Fact]
    public async Task Info_Only_And_Port_Only_Claims_Are_Not_Proof()
    {
        var rule = new R550_BacnetCrossBoundaryDiscoveryReplyRule();
        var forged = Request();
        forged.ApplicationProtocol = null;
        forged.Info = "bacnet.whois I-Am device=999 password=secret";
        Assert.False((await rule.EvaluateAsync(At(forged))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(), 1))).Matched);
    }

    [Theory]
    [InlineData("tcp")]
    [InlineData("tls")]
    [InlineData("dns")]
    [InlineData("wrongport")]
    [InlineData("ipv6")]
    public async Task Contradictory_Transport_Or_Application_Evidence_Fails_Closed(string contradiction)
    {
        var r = Request();
        switch (contradiction)
        {
            case "tcp": r.IsTcp = true; r.IsUdp = false; r.Protocol = "TCP"; break;
            case "tls": r.TlsVersion = "TLS1.3"; break;
            case "dns": r.DnsQname = "example.invalid"; break;
            case "wrongport": r.DestinationPort = 47809; break;
            case "ipv6": r.IpVersion = 6; break;
        }
        Assert.False((await new R550_BacnetCrossBoundaryDiscoveryReplyRule()
            .EvaluateAsync(At(r))).Matched);
    }

    [Fact]
    public async Task Duplicate_Ids_Across_Targets_Cannot_Complete_Threshold()
    {
        var rule = new R550_BacnetCrossBoundaryDiscoveryReplyRule();
        var first = Request(); var firstReply = Reply();
        Assert.False((await rule.EvaluateAsync(At(first))).Matched);
        Assert.False((await rule.EvaluateAsync(At(firstReply, 1))).Matched);
        var second = Request("10.45.2.20"); second.Id = first.Id;
        Assert.False((await rule.EvaluateAsync(At(second, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply("10.45.2.20"), 3))).Matched);
    }

    [Fact]
    public async Task Repeated_Replies_To_One_Target_Do_Not_Create_Two_Pairs()
    {
        var rule = new R550_BacnetCrossBoundaryDiscoveryReplyRule();
        Assert.False((await rule.EvaluateAsync(At(Request()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Request(), 3))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(), 4))).Matched);
    }

    [Fact]
    public async Task Out_Of_Order_And_Unsolicited_Replies_Do_Not_Correlate()
    {
        var rule = new R550_BacnetCrossBoundaryDiscoveryReplyRule();
        Assert.False((await rule.EvaluateAsync(At(Reply(), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Request(), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(), 3))).Matched);
    }

    [Fact]
    public async Task Response_Outside_Sixty_Seconds_Does_Not_Complete_Pair()
    {
        var rule = new R550_BacnetCrossBoundaryDiscoveryReplyRule();
        Assert.False((await rule.EvaluateAsync(At(Request()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(), 61))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Request("10.45.2.20"), 62))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply("10.45.2.20"), 63))).Matched);
    }

    [Fact]
    public async Task Five_Minute_Expiry_Removes_Completed_Pairs()
    {
        var rule = new R550_BacnetCrossBoundaryDiscoveryReplyRule();
        Assert.False((await rule.EvaluateAsync(At(Request()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Request("10.45.2.20"), 302))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply("10.45.2.20"), 303))).Matched);
    }

    [Fact]
    public async Task Different_Public_Sources_Cannot_Combine_One_Pair_Each()
    {
        var rule = new R550_BacnetCrossBoundaryDiscoveryReplyRule();
        Assert.False((await rule.EvaluateAsync(At(Request()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Request("10.45.2.20", "1.1.1.1"), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply("10.45.2.20", "1.1.1.1"), 3))).Matched);
    }

    [Fact]
    public async Task Cooldown_Records_Explicit_Suppression_For_Third_Pair()
    {
        var rule = new R550_BacnetCrossBoundaryDiscoveryReplyRule();
        Assert.True((await TwoPairs(rule)).Matched);
        Assert.False((await rule.EvaluateAsync(At(Request("10.45.3.20"), 4))).Matched);
        var repeated = await rule.EvaluateAsync(At(Reply("10.45.3.20"), 5));
        Assert.True(repeated.Suppressed);
        Assert.Empty(repeated.Events);
    }

    [Fact]
    public async Task Concurrent_Distinct_Replies_Produce_At_Most_One_Match()
    {
        var rule = new R550_BacnetCrossBoundaryDiscoveryReplyRule();
        Assert.False((await rule.EvaluateAsync(At(Request(), 0))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Request("10.45.2.20"), 1))).Matched);
        var results = await Task.WhenAll(
            rule.EvaluateAsync(At(Reply(), 2)).AsTask(),
            rule.EvaluateAsync(At(Reply("10.45.2.20"), 2)).AsTask());
        Assert.Single(results.Where(result => result.Matched));
    }

    [Fact]
    public async Task Raw_Info_And_Claimed_Device_Identity_Are_Not_Emitted()
    {
        var rule = new R550_BacnetCrossBoundaryDiscoveryReplyRule();
        var a = Request(); a.Info = "secret-marker device=987";
        var b = Reply(); b.Info = "secret-marker";
        var c = Request("10.45.2.20"); c.Info = "secret-marker";
        var d = Reply("10.45.2.20"); d.Info = "secret-marker";
        Assert.False((await rule.EvaluateAsync(At(a))).Matched);
        Assert.False((await rule.EvaluateAsync(At(b, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(c, 2))).Matched);
        var result = await rule.EvaluateAsync(At(d, 3));
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains("secret-marker", StringComparison.Ordinal)
                || item.Value.Contains("device=987", StringComparison.Ordinal));
    }

    [Fact]
    public void Registry_Precision_Profile_And_Existing_Floors_Are_Unchanged()
    {
        var rule = new R550_BacnetCrossBoundaryDiscoveryReplyRule();
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Equal(86, rule.PrecisionProfile.MinimumConfidence);
        Assert.Equal(2, rule.PrecisionProfile.Threshold);
        Assert.Single(RuleRegistry.CreateDefaultRules().Where(r => r.Descriptor.RuleId == "R550"));
        Assert.Equal("Rules.R550.Enabled", rule.Descriptor.ConfigKey);
    }
}
