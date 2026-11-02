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

public sealed class R551AdvancedAccuracyBatchTests
{
    private static readonly DateTime Origin = new(2026, 11, 2, 1, 0, 0, DateTimeKind.Utc);
    private static readonly byte[] WhoIsBytes = { 0x81, 0x0a, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08 };
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

    private static TrafficRecord Write(string source = "8.8.8.8", string target = "10.45.1.20",
        byte[]? payload = null, int sourcePort = 40001, int destinationPort = 502)
        => Packet(source, target, true, payload ?? WriteBytes, sourcePort, destinationPort);

    private static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    private static async Task<RuleEvaluationResult> TwoPairs(
        R551_ExternalBacnetDiscoveryThenModbusWriteRule rule,
        string source = "8.8.8.8", string first = "10.45.1.20", string second = "10.45.2.20")
    {
        Assert.False((await rule.EvaluateAsync(At(Discovery(source, first)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(source, first), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Discovery(source, second), 2))).Matched);
        return await rule.EvaluateAsync(At(Write(source, second), 3));
    }

    [Fact]
    public void RealPacketProducer_RecognizesDiscoveryWriteAndReadSeparately()
    {
        var discovery = Discovery();
        var write = Write();
        var read = Write(payload: ReadBytes);
        Assert.Equal("bacnet.whois", discovery.ApplicationProtocol);
        Assert.Equal("modbus.write", write.ApplicationProtocol);
        Assert.Equal("modbus", read.ApplicationProtocol);
        Assert.Equal(8, discovery.L4Len);
        Assert.Equal(12, write.L4Len);
        Assert.True(discovery.IsUdp && write.IsTcp);
    }

    [Fact]
    public async Task TwoOrderedPairsAtDifferentTargetsProduceOneHighCandidate()
    {
        var result = await TwoPairs(new R551_ExternalBacnetDiscoveryThenModbusWriteRule());
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R551", evt.RuleId);
        Assert.Equal(SeverityLevel.High, evt.Severity);
        Assert.Equal(2, evt.Count);
        Assert.Equal(300, evt.WindowSeconds);
        Assert.Contains(evt.StructuredEvidence!.Items, item =>
            item.Key == "pair_max_seconds" && item.Value == "120");
    }

    [Fact]
    public async Task OneTargetOrOneProtocolAloneNeverMeetsTwoPairThreshold()
    {
        var rule = new R551_ExternalBacnetDiscoveryThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Discovery()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Discovery(), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(), 3))).Matched);
        var onlyWrites = new R551_ExternalBacnetDiscoveryThenModbusWriteRule();
        Assert.False((await onlyWrites.EvaluateAsync(At(Write()))).Matched);
        Assert.False((await onlyWrites.EvaluateAsync(At(Write(target: "10.45.2.20"), 1))).Matched);
    }

    [Fact]
    public async Task WriteBeforeDiscoveryDoesNotRetroactivelyCompletePair()
    {
        var rule = new R551_ExternalBacnetDiscoveryThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Write()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Discovery(), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Discovery(target: "10.45.2.20"), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(target: "10.45.2.20"), 3))).Matched);
    }

    [Fact]
    public async Task DifferentPublicSourcesCannotCompleteEachOthersPairs()
    {
        var rule = new R551_ExternalBacnetDiscoveryThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Discovery()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Discovery("1.1.1.1", "10.45.2.20"), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write("1.1.1.1", "10.45.2.20"), 3))).Matched);
    }

    [Fact]
    public async Task DifferentPrivateTargetsCannotBorrowDiscovery()
    {
        var rule = new R551_ExternalBacnetDiscoveryThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Discovery()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(target: "10.45.3.20"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Discovery(target: "10.45.2.20"), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(target: "10.45.2.20"), 3))).Matched);
    }

    [Fact]
    public async Task PrivateSourceCommissioningAndPublicTargetsAreNotExternalPairs()
    {
        var rule = new R551_ExternalBacnetDiscoveryThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Discovery("10.45.1.8", "10.45.1.20")))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write("10.45.1.8", "10.45.1.20"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Discovery("8.8.8.8", "1.1.1.1"), 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write("8.8.8.8", "1.1.1.1"), 3))).Matched);
    }

    [Theory]
    [InlineData("192.0.2.9")]
    [InlineData("198.51.100.9")]
    [InlineData("203.0.113.9")]
    [InlineData("198.18.0.9")]
    [InlineData("100.64.1.9")]
    public async Task DocumentationBenchmarkAndSharedAddressesAreNotPublicSources(string source)
    {
        var result = await TwoPairs(new R551_ExternalBacnetDiscoveryThenModbusWriteRule(),
            source);
        Assert.False(result.Matched);
    }

    [Theory]
    [InlineData("modbus")]
    [InlineData("modbus.read")]
    [InlineData("Modbus Write")]
    public async Task NonWriteOrGuessedOperationCannotCompletePair(string label)
    {
        var rule = new R551_ExternalBacnetDiscoveryThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Discovery()))).Matched);
        var fake = Write();
        fake.ApplicationProtocol = label;
        Assert.False((await rule.EvaluateAsync(At(fake, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Discovery(target: "10.45.2.20"), 2))).Matched);
        var second = Write(target: "10.45.2.20");
        second.ApplicationProtocol = label;
        Assert.False((await rule.EvaluateAsync(At(second, 3))).Matched);
    }

    [Fact]
    public async Task PortOnlyAndInfoOnlyClaimsCannotCompletePair()
    {
        var rule = new R551_ExternalBacnetDiscoveryThenModbusWriteRule();
        var guessed = Discovery(); guessed.ApplicationProtocol = null; guessed.Info = "bacnet.whois";
        Assert.False((await rule.EvaluateAsync(At(guessed))).Matched);
        var write = Write(); write.ApplicationProtocol = null; write.Info = "modbus.write password=secret";
        Assert.False((await rule.EvaluateAsync(At(write, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(target: "10.45.2.20"), 2))).Matched);
    }

    [Fact]
    public async Task TruncatedAndContradictoryWireFramesDoNotBecomeQualifiedOperations()
    {
        var badBvlc = Discovery(payload: new byte[] { 0x81, 0x0a, 0x00, 0x09, 0x01, 0x00, 0x10, 0x08 });
        var shortModbus = Write(payload: new byte[] { 0, 1, 0, 0, 0, 6, 1, 6, 0, 1, 0 });
        var wrongLength = Write(payload: new byte[] { 0, 1, 0, 0, 0, 7, 1, 6, 0, 1, 0, 2 });
        Assert.NotEqual("bacnet.whois", badBvlc.ApplicationProtocol);
        Assert.NotEqual("modbus.write", shortModbus.ApplicationProtocol);
        Assert.NotEqual("modbus.write", wrongLength.ApplicationProtocol);
        var rule = new R551_ExternalBacnetDiscoveryThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(badBvlc))).Matched);
        Assert.False((await rule.EvaluateAsync(At(shortModbus, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(wrongLength, 2))).Matched);
    }

    [Fact]
    public async Task ContradictoryTransportAndApplicationMetadataFailClosed()
    {
        var rule = new R551_ExternalBacnetDiscoveryThenModbusWriteRule();
        var badDiscovery = Discovery(); badDiscovery.IsTcp = true; badDiscovery.Protocol = "TCP";
        var tlsWrite = Write(); tlsWrite.TlsVersion = "TLS1.3";
        var dnsWrite = Write(); dnsWrite.DnsQname = "example.test";
        var httpWrite = Write(); httpWrite.HttpRequestHeaders = "Authorization: secret";
        var wrongPort = Write(destinationPort: 503);
        Assert.False((await rule.EvaluateAsync(At(badDiscovery))).Matched);
        Assert.False((await rule.EvaluateAsync(At(tlsWrite, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(dnsWrite, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(httpWrite, 3))).Matched);
        Assert.False((await rule.EvaluateAsync(At(wrongPort, 4))).Matched);
    }

    [Fact]
    public async Task DuplicatePacketIdAcrossTargetsCannotCompleteSecondPair()
    {
        var rule = new R551_ExternalBacnetDiscoveryThenModbusWriteRule();
        var firstDiscovery = Discovery();
        Assert.False((await rule.EvaluateAsync(At(firstDiscovery))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(), 1))).Matched);
        var duplicate = Discovery(target: "10.45.2.20"); duplicate.Id = firstDiscovery.Id;
        Assert.False((await rule.EvaluateAsync(At(duplicate, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(target: "10.45.2.20"), 3))).Matched);
    }

    [Fact]
    public async Task OutOfOrderObservationCannotCompleteSecondPair()
    {
        var rule = new R551_ExternalBacnetDiscoveryThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Discovery(), 20))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(), 21))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Discovery(target: "10.45.2.20"), 10))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(target: "10.45.2.20"), 22))).Matched);
    }

    [Fact]
    public async Task PairOlderThanTwoMinutesCannotComplete()
    {
        var rule = new R551_ExternalBacnetDiscoveryThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Discovery()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(), 121))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Discovery(target: "10.45.2.20"), 122))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(target: "10.45.2.20"), 123))).Matched);
    }

    [Fact]
    public async Task ExactlyTwoMinutePairBoundaryIsIncluded()
    {
        var rule = new R551_ExternalBacnetDiscoveryThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Discovery()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(), 120))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Discovery(target: "10.45.2.20"), 121))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Write(target: "10.45.2.20"), 241))).Matched);
    }

    [Fact]
    public async Task CompletedPairOlderThanFiveMinutesExpires()
    {
        var rule = new R551_ExternalBacnetDiscoveryThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Discovery()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Discovery(target: "10.45.2.20"), 302))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(target: "10.45.2.20"), 303))).Matched);
    }

    [Fact]
    public async Task NewPairsDuringCooldownAreSuppressedWithoutEvents()
    {
        var rule = new R551_ExternalBacnetDiscoveryThenModbusWriteRule();
        Assert.True((await TwoPairs(rule)).Matched);
        Assert.False((await rule.EvaluateAsync(At(Discovery(target: "10.45.3.20"), 10))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Write(target: "10.45.3.20"), 11))).Suppressed);
        Assert.False((await rule.EvaluateAsync(At(Discovery(target: "10.45.4.20"), 12))).Matched);
        var result = await rule.EvaluateAsync(At(Write(target: "10.45.4.20"), 13));
        Assert.True(result.Suppressed);
        Assert.Empty(result.Events);
    }

    [Fact]
    public async Task ConcurrentSecondStageWritesEmitAtMostOneMatch()
    {
        var rule = new R551_ExternalBacnetDiscoveryThenModbusWriteRule();
        Assert.False((await rule.EvaluateAsync(At(Discovery()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Discovery(target: "10.45.2.20"), 1))).Matched);
        var results = await Task.WhenAll(
            rule.EvaluateAsync(At(Write(), 2)).AsTask(),
            rule.EvaluateAsync(At(Write(target: "10.45.2.20"), 2)).AsTask());
        Assert.Single(results.Where(result => result.Matched));
    }

    [Fact]
    public async Task RawInfoAndRegisterValuesNeverEnterEventEvidence()
    {
        var rule = new R551_ExternalBacnetDiscoveryThenModbusWriteRule();
        var a = Discovery(); a.Info = "password=secret-marker";
        var b = Write(); b.Info = "register=987 secret-marker";
        var c = Discovery(target: "10.45.2.20"); c.Info = "secret-marker";
        var d = Write(target: "10.45.2.20"); d.Info = "secret-marker";
        Assert.False((await rule.EvaluateAsync(At(a))).Matched);
        Assert.False((await rule.EvaluateAsync(At(b, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(c, 2))).Matched);
        var result = await rule.EvaluateAsync(At(d, 3));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains("secret-marker", StringComparison.Ordinal)
                || item.Value.Contains("register=987", StringComparison.Ordinal));
    }

    [Fact]
    public void RegistryAndCandidateShadowConfidencePolicyRemainExplicit()
    {
        var rule = new R551_ExternalBacnetDiscoveryThenModbusWriteRule();
        Assert.Equal("Rules.R551.Enabled", rule.Descriptor.ConfigKey);
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Equal(90, rule.PrecisionProfile.MinimumConfidence);
        Assert.Single(RuleRegistry.CreateDefaultRules().Where(r => r.Descriptor.RuleId == "R551"));
        Assert.True(RulePrecisionCatalog.Validate("R551", Write()).CanEvaluate);
    }

    [Fact]
    public async Task SaturatedTargetBucketFailsClosedForNewTargets()
    {
        var rule = new R551_ExternalBacnetDiscoveryThenModbusWriteRule();
        for (var i = 0; i < 32; i++)
            Assert.False((await rule.EvaluateAsync(At(Discovery(target: "10.45.1." + (i + 20))))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Discovery(target: "10.45.2.99"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Write(target: "10.45.2.99"), 2))).Matched);
    }
}
