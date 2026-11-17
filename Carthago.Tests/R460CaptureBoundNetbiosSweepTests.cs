// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Execution;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using PacketDotNet;
using Xunit;

namespace Carthago.Tests;

public sealed class R460CaptureBoundNetbiosSweepTests
{
    private static readonly DateTime Epoch = new(2026, 11, 17, 10, 0, 0, DateTimeKind.Utc);

    private static byte[] Query(string name, bool response = false)
    {
        if (name.Length > 15) throw new ArgumentException("NetBIOS names must fit the 15-character field.");
        var payload = new byte[50];
        payload[0] = 0x12; payload[1] = 0x34; // Transaction ID
        payload[2] = response ? (byte)0x80 : (byte)0x00; // Query/response
        payload[3] = 0x10; // NBNS broadcast query bit
        payload[5] = 1; // One question
        payload[12] = 32; // NetBIOS first-level encoded name length
        for (var i = 0; i < 16; i++)
        {
            byte octet = i == 15 ? (byte)0 : i < name.Length ? (byte)name[i] : (byte)' ';
            payload[13 + i * 2] = (byte)('A' + (octet >> 4));
            payload[14 + i * 2] = (byte)('A' + (octet & 0x0F));
        }
        payload[45] = 0; // DNS name terminator
        payload[47] = 0x20; // NB question type
        payload[49] = 1; // IN question class
        return payload;
    }

    private static TrafficRecord Captured(string name, string source = "192.168.50.10",
        bool response = false, bool wrongPort = false, bool malformed = false,
        bool truncated = false)
    {
        var payload = Query(name, response);
        if (malformed) payload[13] = (byte)'Z'; // Invalid A..P nibble
        if (truncated) payload = payload[..^1];
        var frame = new byte[14 + 20 + 8 + payload.Length];
        for (var i = 0; i < 6; i++) frame[i] = 0xFF;
        frame[6] = 0x02; frame[7] = 0x11; frame[8] = 0x22;
        frame[9] = 0x33; frame[10] = 0x44; frame[11] = 0x55;
        frame[12] = 8; frame[13] = 0; // Ethernet IPv4
        frame[14] = 0x45; // IPv4, no options
        int totalIp = 20 + 8 + payload.Length;
        frame[16] = (byte)(totalIp >> 8);
        frame[17] = (byte)totalIp;
        frame[22] = 64; frame[23] = 17; // UDP
        IPAddress.Parse(source).GetAddressBytes().CopyTo(frame, 26);
        IPAddress.Parse("192.168.50.1").GetAddressBytes().CopyTo(frame, 30);
        frame[34] = 0xC3; frame[35] = 0x50; // Ephemeral source port 50000
        frame[36] = 0; frame[37] = wrongPort ? (byte)138 : (byte)137;
        int udpLength = 8 + payload.Length;
        frame[38] = (byte)(udpLength >> 8);
        frame[39] = (byte)udpLength;
        payload.CopyTo(frame, 42);
        return Assert.IsType<TrafficRecord>(
            new PacketHandler().ParseFrame(frame, LinkLayers.Ethernet));
    }

    private static Task<RuleEvaluationResult> Eval(
        R460_NetBIOSNameQuerySweepRule rule, TrafficRecord record, DateTime at)
        => rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, at)).AsTask();

    [Fact]
    public async Task EightDistinctCaptureDecodedNamesProduceShadowOnlyCandidate()
    {
        var rule = new R460_NetBIOSNameQuerySweepRule();
        for (var i = 0; i < 7; i++)
            Assert.False((await Eval(rule, Captured("NODE" + i), Epoch.AddSeconds(i))).Matched);
        var result = await Eval(rule, Captured("NODE7"), Epoch.AddSeconds(7));
        Assert.True(result.Matched);
        Assert.False(result.Suppressed);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("NODE7", evt.Evidence ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            x => x.Value.Contains("NODE7", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(76, rule.PrecisionProfile.MinimumConfidence);
        Assert.Equal(8, rule.PrecisionProfile.Threshold);
    }

    [Fact]
    public async Task SameNetbiosNameAcrossIndependentPacketsDoesNotCountAsSweep()
    {
        var rule = new R460_NetBIOSNameQuerySweepRule();
        for (var i = 0; i < 18; i++)
            Assert.False((await Eval(rule, Captured("SAMEHOST"),
                Epoch.AddSeconds(i))).Matched);
    }

    [Fact]
    public async Task ValidResponseWrongPortBadEncodingAndTruncatedFrameCannotQualify()
    {
        var rule = new R460_NetBIOSNameQuerySweepRule();
        for (var i = 0; i < 12; i++)
        {
            var response = Captured("NODE" + i, response: true);
            Assert.Null(response.NbnsQueryNameDigest);
            Assert.False((await Eval(rule, response, Epoch.AddSeconds(i))).Matched);
            var wrongPort = Captured("NODE" + i, wrongPort: true);
            Assert.Null(wrongPort.NbnsQueryNameDigest);
            Assert.False((await Eval(rule, wrongPort, Epoch.AddSeconds(i))).Matched);
            var malformed = Captured("NODE" + i, malformed: true);
            Assert.Null(malformed.NbnsQueryNameDigest);
            Assert.False((await Eval(rule, malformed, Epoch.AddSeconds(i))).Matched);
            var truncated = Captured("NODE" + i, truncated: true);
            Assert.Null(truncated.NbnsQueryNameDigest);
            Assert.False((await Eval(rule, truncated, Epoch.AddSeconds(i))).Matched);
        }
    }

    [Fact]
    public async Task ImportedTextAndPortFieldsCannotForgeCaptureProvenance()
    {
        var rule = new R460_NetBIOSNameQuerySweepRule();
        for (var i = 0; i < 12; i++)
        {
            var invented = new TrafficRecord
            {
                Source = "192.168.50.10", Destination = "192.168.50.1",
                IsUdp = true, Protocol = "UDP", IpVersion = 4,
                SourcePort = 50000, DestinationPort = 137, L4Len = 50,
                Info = "NBNS distinct name sweep attack attempt",
                DnsQname = "internal" + i + ".local"
            };
            Assert.False((await Eval(rule, invented, Epoch.AddSeconds(i))).Matched);
        }
    }

    [Fact]
    public async Task IndependentSourceHostsCannotCombineNamesIntoSingleSweep()
    {
        var rule = new R460_NetBIOSNameQuerySweepRule();
        for (var i = 0; i < 7; i++)
        {
            Assert.False((await Eval(rule, Captured("HOST" + i, "192.168.50.10"),
                Epoch.AddSeconds(i))).Matched);
            Assert.False((await Eval(rule, Captured("HOST" + i, "192.168.50.11"),
                Epoch.AddSeconds(i))).Matched);
        }
        Assert.True((await Eval(rule, Captured("HOST7", "192.168.50.10"),
            Epoch.AddSeconds(7))).Matched);
    }

    [Fact]
    public async Task PacketIdReplayAndOutOfOrderCannotIncreaseCount()
    {
        var rule = new R460_NetBIOSNameQuerySweepRule();
        var same = Captured("FIRST");
        for (var i = 0; i < 20; i++)
            Assert.False((await Eval(rule, same, Epoch.AddSeconds(i))).Matched);
        Assert.False((await Eval(rule, Captured("LEAD"),
            Epoch.AddSeconds(20))).Matched);
        Assert.False((await Eval(rule, Captured("OLD"),
            Epoch.AddSeconds(1))).Matched); // Older than last unique frame
        for (var i = 0; i < 5; i++)
            Assert.False((await Eval(rule, Captured("NEW" + i),
                Epoch.AddSeconds(21 + i))).Matched);
        Assert.True((await Eval(rule, Captured("LAST"), Epoch.AddSeconds(26))).Matched);
    }

    [Fact]
    public async Task WindowExpirationAndCooldownAreBounded()
    {
        var rule = new R460_NetBIOSNameQuerySweepRule();
        for (var i = 0; i < 7; i++)
            Assert.False((await Eval(rule, Captured("NAME" + i),
                Epoch.AddSeconds(i))).Matched);
        Assert.False((await Eval(rule, Captured("LATE"),
            Epoch.AddMinutes(2))).Matched);
        for (var i = 0; i < 6; i++)
            Assert.False((await Eval(rule, Captured("AGAIN" + i),
                Epoch.AddMinutes(2).AddSeconds(i + 1))).Matched);
        var result = await Eval(rule, Captured("AGAIN6"),
            Epoch.AddMinutes(2).AddSeconds(7));
        Assert.True(result.Matched);
        result = await Eval(rule, Captured("AGAIN7"),
            Epoch.AddMinutes(2).AddSeconds(8));
        Assert.True(result.Matched);
        Assert.True(result.Suppressed);
    }

    [Fact]
    public void CaptureDerivedUdpIsSelectableWithoutDnsMetadata()
    {
        var rule = new R460_NetBIOSNameQuerySweepRule();
        var record = Captured("HOST");
        Assert.False(string.IsNullOrEmpty(record.NbnsQueryNameDigest));
        var plan = new RuleCandidateSelector().CreatePlan(
            new IDetectionRule[] { rule }, record);
        Assert.True(Assert.Single(plan.Entries).ShouldEvaluate);
        Assert.DoesNotContain(RuleTelemetryKind.Dns, rule.PrecisionProfile.RequiredTelemetry);
        Assert.DoesNotContain(RuleTelemetryKind.Payload, rule.PrecisionProfile.RequiredTelemetry);
        Assert.True(RuleTelemetryValidator.Validate(rule, record).CanRunSafely);
    }
}
