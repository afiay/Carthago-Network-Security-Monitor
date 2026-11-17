// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Net;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Execution;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.ProtocolIntelligence;
using PacketDotNet;
using Xunit;

namespace Carthago.Tests;

public sealed class R474CaptureModbusForceListenOnlyTests
{
    private static readonly DateTime Epoch = new(2026, 11, 17, 11, 0, 0, DateTimeKind.Utc);

    // FC08 diagnostics / subfunction 0x0004 / data 0x0000.
    private static byte[] Request()
        => new byte[] { 0x12, 0x34, 0, 0, 0, 6, 1, 8, 0, 4, 0, 0 };

    private static TrafficRecord Frame(PacketHandler handler, byte[] data,
        bool client = true, uint seq = 101, uint ack = 201, byte flags = 0x18,
        int clientPort = 51000, int serverPort = 502,
        string source = "192.168.50.10", string target = "192.168.50.20")
    {
        var frame = new byte[40 + data.Length];
        frame[0] = 0x45; frame[8] = 64; frame[9] = 6; // IPv4/TCP
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(2, 2), (ushort)frame.Length);
        IPAddress.Parse(client ? source : target).GetAddressBytes().CopyTo(frame, 12);
        IPAddress.Parse(client ? target : source).GetAddressBytes().CopyTo(frame, 16);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(20, 2), (ushort)(client ? clientPort : serverPort));
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(22, 2), (ushort)(client ? serverPort : clientPort));
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(24, 4), seq);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(28, 4), ack);
        frame[32] = 0x50; frame[33] = flags;
        data.CopyTo(frame, 40);
        return Assert.IsType<TrafficRecord>(handler.ParseFrame(frame, (LinkLayers)12));
    }

    private static TrafficRecord Captured(byte[]? data = null, bool includeSynAck = true,
        bool includeSyn = true, uint ack = 201, int serverPort = 502,
        string source = "192.168.50.10", string target = "192.168.50.20",
        byte firstFlags = 0x18)
    {
        var handler = new PacketHandler();
        if (includeSyn)
            Frame(handler, Array.Empty<byte>(), seq: 100, ack: 0, flags: 2,
                serverPort: serverPort, source: source, target: target);
        if (includeSynAck)
            Frame(handler, Array.Empty<byte>(), client: false, seq: 200, ack: 101,
                flags: 0x12, serverPort: serverPort, source: source, target: target);
        return Frame(handler, data ?? Request(), ack: ack,
            flags: firstFlags, serverPort: serverPort, source: source, target: target);
    }

    private static Task<RuleEvaluationResult> Eval(R474_ModbusForceListenOnlyModeAttemptRule rule,
        TrafficRecord record, int seconds = 0)
        => rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, Epoch.AddSeconds(seconds))).AsTask();

    [Fact]
    public async Task CompleteFirstNativeModbusRequestProducesAttemptOnlyInShadow()
    {
        var record = Captured();
        Assert.True(record.ModbusForceListenOnlyModeAttemptObserved);
        Assert.Equal("modbus.tcp.force_listen_only.attempt", record.ApplicationProtocol);
        var rule = new R474_ModbusForceListenOnlyModeAttemptRule();
        var result = await Eval(rule, record);
        Assert.True(result.Matched);
        Assert.False(result.Suppressed);
        Assert.Single(result.Events);
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Equal(86, rule.PrecisionProfile.MinimumConfidence);
        Assert.Equal(1, rule.PrecisionProfile.Threshold);
    }

    [Theory]
    [InlineData(2, 1)]
    [InlineData(5, 5)]
    [InlineData(6, 0)]
    [InlineData(6, 248)]
    [InlineData(7, 6)]
    [InlineData(8, 1)]
    [InlineData(9, 3)]
    [InlineData(10, 1)]
    [InlineData(11, 1)]
    public async Task AlternativeOrMalformedModbusAduCannotTrigger(int offset, int value)
    {
        var packet = Request();
        packet[offset] = (byte)value;
        Assert.False(ModbusForceListenOnlyModeInspector.TryInspect(packet));
        var record = Captured(packet);
        Assert.False(record.ModbusForceListenOnlyModeAttemptObserved);
        Assert.False((await Eval(new R474_ModbusForceListenOnlyModeAttemptRule(), record)).Matched);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(1)]
    public async Task TruncatedOrCoalescedPayloadDoesNotMakeExactSingleRequest(int delta)
    {
        var request = Request();
        var data = delta == -1 ? request[..^1] : new byte[request.Length + 1];
        if (delta == 1) Array.Copy(request, data, request.Length);
        Assert.False(ModbusForceListenOnlyModeInspector.TryInspect(data));
        var record = Captured(data);
        Assert.False(record.ModbusForceListenOnlyModeAttemptObserved);
        Assert.False((await Eval(new R474_ModbusForceListenOnlyModeAttemptRule(), record)).Matched);
    }

    [Fact]
    public async Task MissingSessionAnchorsWrongAcknowledgmentAndWrongDestinationFailClosed()
    {
        foreach (var record in new[]
        {
            Captured(includeSyn: false),
            Captured(includeSynAck: false),
            Captured(ack: 202),
            Captured(serverPort: 1502),
            Captured(firstFlags: 0x10)
        })
        {
            Assert.False(record.ModbusForceListenOnlyModeAttemptObserved);
            Assert.False((await Eval(new R474_ModbusForceListenOnlyModeAttemptRule(), record)).Matched);
        }
    }

    [Fact]
    public async Task UntrustedLabelsAndPortsCannotForgeCaptureOnlyFlag()
    {
        var record = new TrafficRecord
        {
            Source = "192.168.50.10", Destination = "192.168.50.20",
            IsTcp = true, IpVersion = 4, SourcePort = 51000, DestinationPort = 502,
            Protocol = "TCP", ApplicationProtocol = "modbus.tcp.force_listen_only.attempt",
            Info = "force listen only mode", Length = 900, L4Len = 12
        };
        Assert.False(record.ModbusForceListenOnlyModeAttemptObserved);
        Assert.False((await Eval(new R474_ModbusForceListenOnlyModeAttemptRule(), record)).Matched);
    }

    [Fact]
    public async Task PacketIdReplayCannotCreateSecondFinding()
    {
        var rule = new R474_ModbusForceListenOnlyModeAttemptRule();
        var first = Captured();
        Assert.True((await Eval(rule, first)).Matched);
        Assert.False((await Eval(rule, first, 1)).Matched);
        var second = Captured();
        var suppressed = await Eval(rule, second, 2);
        Assert.True(suppressed.Matched);
        Assert.True(suppressed.Suppressed);
    }

    [Fact]
    public async Task DifferentSourceIsIndependentOfCooldown()
    {
        var rule = new R474_ModbusForceListenOnlyModeAttemptRule();
        Assert.True((await Eval(rule, Captured(), 0)).Matched);
        var other = Captured(source: "192.168.50.11");
        var result = await Eval(rule, other, 1);
        Assert.True(result.Matched);
        Assert.False(result.Suppressed);
    }

    [Fact]
    public void EngineSelectorAndTelemetryValidatorAcceptActualCaptureEvidence()
    {
        var rule = new R474_ModbusForceListenOnlyModeAttemptRule();
        var record = Captured();
        var plan = new RuleCandidateSelector().CreatePlan(
            new IDetectionRule[] { rule }, record);
        Assert.True(Assert.Single(plan.Entries).ShouldEvaluate);
        Assert.True(RuleTelemetryValidator.Validate(rule, record).CanRunSafely);
        Assert.DoesNotContain(RuleTelemetryKind.Payload, rule.PrecisionProfile.RequiredTelemetry);
        Assert.DoesNotContain(RuleTelemetryKind.OtIcsProtocol, rule.PrecisionProfile.RequiredTelemetry);
    }
}
