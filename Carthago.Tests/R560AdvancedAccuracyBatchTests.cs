// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed.
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

public sealed class R560AdvancedAccuracyBatchTests
{
    private static readonly DateTime Origin = new(2026, 11, 2, 1, 0, 0, DateTimeKind.Utc);
    private static readonly byte[] WhoIsBytes = { 0x81, 0x0a, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08 };
    // Synthetic I-Am-shaped BACnet datagram, not a verified device identity.
    private static readonly byte[] IAmBytes =
    {
        0x81, 0x0a, 0x00, 0x15, 0x01, 0x00, 0x10, 0x00,
        0xc4, 0x02, 0x00, 0x00, 0x01, 0x22, 0x05, 0xc4,
        0x91, 0x03, 0x22, 0x00, 0x0f
    };
    // Synthetic MBAP + function 06 (write single holding register); no real controller or register values.
    private static readonly byte[] WriteBytes = { 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x01, 0x00, 0x02 };
    private static readonly byte[] ReadBytes = { 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x01, 0x00, 0x02 };

    private static TrafficRecord Packet(string source, string destination, bool tcp,
        byte[] payload, int sourcePort, int destinationPort)
    {
        var transportHeader = tcp ? 20 : 8;
        var frame = new byte[20 + transportHeader + payload.Length];
        frame[0] = 0x45;
        frame[2] = (byte)(frame.Length >> 8);
        frame[3] = (byte)frame.Length;
        frame[8] = 64;
        frame[9] = (byte)(tcp ? 6 : 17);
        IPAddress.Parse(source).GetAddressBytes().CopyTo(frame, 12);
        IPAddress.Parse(destination).GetAddressBytes().CopyTo(frame, 16);
        frame[20] = (byte)(sourcePort >> 8);
        frame[21] = (byte)sourcePort;
        frame[22] = (byte)(destinationPort >> 8);
        frame[23] = (byte)destinationPort;
        if (tcp)
        {
            frame[32] = 0x50; // TCP header length 20 bytes.
            frame[33] = 0x18; // PSH, ACK; first visible payload, not an authenticated session.
        }
        else
        {
            var udpLength = payload.Length + 8;
            frame[24] = (byte)(udpLength >> 8);
            frame[25] = (byte)udpLength;
        }
        payload.CopyTo(frame, 20 + transportHeader);
        var record = new PacketHandler().ParseFrame(frame, (PacketDotNet.LinkLayers)12);
        Assert.NotNull(record);
        return record!;
    }

    private static TrafficRecord Discovery(string source = "8.8.8.8", string target = "10.45.1.20",
        byte[]? payload = null)
        => Packet(source, target, false, payload ?? WhoIsBytes, 47808, 47808);

    private static TrafficRecord Reply(string source = "10.45.1.20", string target = "8.8.8.8",
        byte[]? payload = null)
        => Packet(source, target, false, payload ?? IAmBytes, 47808, 47808);

    private static TrafficRecord Write(string source = "8.8.8.8", string target = "10.45.1.20",
        byte[]? payload = null, int sourcePort = 40001, int destinationPort = 502)
        => Packet(source, target, true, payload ?? WriteBytes, sourcePort, destinationPort);

    private static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    private static async Task<RuleEvaluationResult> Triple(
        R560_ExternalBacnetReplyThenModbusWriteRule rule,
        string publicIp = "8.8.8.8", string target = "10.45.1.20", int start = 0)
    {
        Assert.False((await rule.EvaluateAsync(At(Discovery(publicIp, target), start))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(target, publicIp), start + 1))).Matched);
        return await rule.EvaluateAsync(At(Write(publicIp, target), start + 2));
    }

    [Fact]
    public void PacketHandlerProducesThreeDistinctTypedPacketShapes()
    {
        Assert.Equal("bacnet.whois", Discovery().ApplicationProtocol);
        Assert.Equal("bacnet.iam", Reply().ApplicationProtocol);
        Assert.Equal("modbus.write", Write().ApplicationProtocol);
        Assert.Equal("modbus", Write(payload: ReadBytes).ApplicationProtocol);
        Assert.Equal(8, Discovery().L4Len);
        Assert.Equal(21, Reply().L4Len);
        Assert.Equal(12, Write().L4Len);
    }

    [Fact]
    public async Task SingleTargetOrderedThreeStageSequenceMatches()
    {
        var result = await Triple(new R560_ExternalBacnetReplyThenModbusWriteRule());
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R560", evt.RuleId);
        Assert.Equal(SeverityLevel.High, evt.Severity);
        Assert.Equal(1, evt.Count);
        Assert.Equal(300, evt.WindowSeconds);
    }

    [Fact]
    public async Task MissingReplyOrWriteCannotComplete()
    {
        var rule = new R560_ExternalBacnetReplyThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Discovery()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(), 1))).Matched);
        var onlyReply = new R560_ExternalBacnetReplyThenModbusWriteRule();
        Assert.False((await onlyReply.EvaluateAsync(At(Reply()))).Matched);
        Assert.False((await onlyReply.EvaluateAsync(At(Write(), 1))).Matched);
        var noWrite = new R560_ExternalBacnetReplyThenModbusWriteRule();
        Assert.False((await noWrite.EvaluateAsync(At(Discovery()))).Matched);
        Assert.False((await noWrite.EvaluateAsync(At(Reply(), 1))).Matched);
    }

    [Fact]
    public async Task WrongPublicPeerOrPrivateTargetCannotBorrowReply()
    {
        var rule = new R560_ExternalBacnetReplyThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Discovery()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(target: "1.1.1.1"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(), 2))).Matched);
        var second = new R560_ExternalBacnetReplyThenModbusWriteRule();
        Assert.False((await second.EvaluateAsync(At(Discovery()))).Matched);
        Assert.False((await second.EvaluateAsync(At(Reply(source: "10.45.2.20"), 1))).Matched);
        Assert.False((await second.EvaluateAsync(At(Write(), 2))).Matched);
    }

    [Fact]
    public async Task ReorderedReplyAndWriteNeverRetroactivelyComplete()
    {
        var rule = new R560_ExternalBacnetReplyThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Write()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Discovery(), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(), 3))).Matched);
    }

    [Fact]
    public async Task MalformedBvlcAndModbusFramesDoNotQualify()
    {
        var badBvlc = Discovery(payload: new byte[] { 0x81, 0x0a, 0x00, 0x09, 0x01, 0x00, 0x10, 0x08 });
        var shortReply = Reply(payload: new byte[] { 0x81, 0x0a, 0x00, 0x08, 0x01, 0x00, 0x10, 0x00 });
        var badModbus = Write(payload: new byte[] { 0, 1, 0, 0, 0, 7, 1, 6, 0, 1, 0, 2 });
        Assert.NotEqual("bacnet.whois", badBvlc.ApplicationProtocol);
        Assert.NotEqual("modbus.write", badModbus.ApplicationProtocol);
        var rule = new R560_ExternalBacnetReplyThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(badBvlc))).Matched);
        Assert.False((await rule.EvaluateAsync(At(shortReply, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(badModbus, 2))).Matched);
    }

    [Fact]
    public async Task GuessedInfoAndPortOnlyDoNotCreateProtocolEvidence()
    {
        var rule = new R560_ExternalBacnetReplyThenModbusWriteRule();
        var a = Discovery(); a.ApplicationProtocol = null; a.Info = "bacnet.whois password=secret";
        var b = Reply(); b.ApplicationProtocol = null; b.Info = "bacnet.iam secret";
        var c = Write(); c.ApplicationProtocol = null; c.Info = "modbus.write secret";
        Assert.False((await rule.EvaluateAsync(At(a))).Matched);
        Assert.False((await rule.EvaluateAsync(At(b, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(c, 2))).Matched);
    }

    [Fact]
    public async Task ContradictoryTransportAndApplicationMetadataFailClosed()
    {
        var rule = new R560_ExternalBacnetReplyThenModbusWriteRule();
        var badRequest = Discovery(); badRequest.IsTcp = true; badRequest.Protocol = "TCP";
        var badReply = Reply(); badReply.TlsVersion = "TLS1.3";
        var badWrite = Write(); badWrite.DnsQname = "example.invalid";
        var wrongPort = Write(destinationPort: 503);
        Assert.False((await rule.EvaluateAsync(At(badRequest))).Matched);
        Assert.False((await rule.EvaluateAsync(At(badReply, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(badWrite, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(wrongPort, 3))).Matched);
    }

    [Theory]
    [InlineData("192.0.2.9")]
    [InlineData("198.51.100.9")]
    [InlineData("203.0.113.9")]
    [InlineData("198.18.0.9")]
    [InlineData("100.64.1.9")]
    [InlineData("10.1.1.9")]
    public async Task NonPublicSourcesAreRejected(string source)
    {
        var result = await Triple(new R560_ExternalBacnetReplyThenModbusWriteRule(), publicIp: source);
        Assert.False(result.Matched);
    }

    [Fact]
    public async Task ModbusReadAndResponseLabelsAreNotWriteRequests()
    {
        var rule = new R560_ExternalBacnetReplyThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Discovery()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(payload: ReadBytes), 2))).Matched);
        var response = Write(); response.ApplicationProtocol = "modbus.response";
        Assert.False((await rule.EvaluateAsync(At(response, 3))).Matched);
    }

    [Fact]
    public async Task DuplicateIdsCannotAdvanceThreeStages()
    {
        var rule = new R560_ExternalBacnetReplyThenModbusWriteRule();
        var a = Discovery(); var b = Reply(); b.Id = a.Id;
        Assert.False((await rule.EvaluateAsync(At(a))).Matched);
        Assert.False((await rule.EvaluateAsync(At(b, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(), 2))).Matched);
    }

    [Fact]
    public async Task OutOfOrderObservationCannotComplete()
    {
        var rule = new R560_ExternalBacnetReplyThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Discovery(), 20))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(), 19))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(), 21))).Matched);
    }

    [Fact]
    public async Task ReplyAfterSixtySecondsCannotAdvance()
    {
        var rule = new R560_ExternalBacnetReplyThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Discovery()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(), 61))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(), 62))).Matched);
    }

    [Fact]
    public async Task WriteAfterOneHundredTwentySecondsCannotComplete()
    {
        var rule = new R560_ExternalBacnetReplyThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Discovery()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(), 122))).Matched);
    }

    [Fact]
    public async Task ExactReplyAndWriteTimeBoundariesAreIncluded()
    {
        var rule = new R560_ExternalBacnetReplyThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Discovery()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(), 60))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Write(), 180))).Matched);
    }

    [Fact]
    public async Task CooldownProducesSuppressedMatchNotNewEvent()
    {
        var rule = new R560_ExternalBacnetReplyThenModbusWriteRule();
        Assert.True((await Triple(rule)).Matched);
        var result = await Triple(rule, target: "10.45.2.20", start: 10);
        Assert.True(result.Suppressed);
        Assert.Empty(result.Events);
    }

    [Fact]
    public async Task EventEvidenceDoesNotExposeInfoOrRegisterValues()
    {
        var rule = new R560_ExternalBacnetReplyThenModbusWriteRule();
        var a = Discovery(); a.Info = "secret-marker";
        var b = Reply(); b.Info = "device=secret-marker";
        var c = Write(); c.Info = "register=987 secret-marker";
        Assert.False((await rule.EvaluateAsync(At(a))).Matched);
        Assert.False((await rule.EvaluateAsync(At(b, 1))).Matched);
        var result = await rule.EvaluateAsync(At(c, 2));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains("secret-marker", StringComparison.Ordinal)
                || item.Value.Contains("register=987", StringComparison.Ordinal));
    }

    [Fact]
    public void RegistryAndShadowConfidencePolicyAreExplicit()
    {
        var rule = new R560_ExternalBacnetReplyThenModbusWriteRule();
        Assert.Equal("Rules.R560.Enabled", rule.Descriptor.ConfigKey);
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Equal(90, rule.PrecisionProfile.MinimumConfidence);
        Assert.Single(RuleRegistry.CreateDefaultRules().Where(r => r.Descriptor.RuleId == "R560"));
        Assert.True(RulePrecisionCatalog.Validate("R560", Write()).CanEvaluate);
    }

    [Fact]
    public async Task SaturatedTargetBucketFailsClosedForNewTargets()
    {
        var rule = new R560_ExternalBacnetReplyThenModbusWriteRule();
        for (var i = 0; i < 16; i++)
            Assert.False((await rule.EvaluateAsync(At(Discovery(target: "10.45.1." + (i + 20))))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Discovery(target: "10.45.2.99"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(source: "10.45.2.99"), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(target: "10.45.2.99"), 3))).Matched);
    }

    [Fact]
    public async Task ConcurrentWriteRequestsProduceAtMostOneEvent()
    {
        var rule = new R560_ExternalBacnetReplyThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Discovery()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(), 1))).Matched);
        var results = await Task.WhenAll(
            rule.EvaluateAsync(At(Write(), 2)).AsTask(),
            rule.EvaluateAsync(At(Write(), 2)).AsTask());
        Assert.Single(results.Where(result => result.Matched));
    }

    [Fact]
    public async Task ObservationOutsideFiveMinutesCannotComplete()
    {
        var rule = new R560_ExternalBacnetReplyThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Discovery()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Reply(), 60))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(), 361))).Matched);
    }
}
