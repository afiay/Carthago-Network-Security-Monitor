// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Synthetic packet fixtures, never live plant traffic.
using System;
using System.Reflection;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Carthago.Tests.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests;

public sealed class BacnetDeviceCommunicationControlCaptureTests
{
    private static TrafficRecord ParseIpv6Datagram(byte[] payload, bool atomicFragmentHeader)
    {
        int extraHeader = atomicFragmentHeader ? 8 : 0;
        var packet = new byte[40 + extraHeader + 8 + payload.Length];
        packet[0] = 0x60;
        int ipv6PayloadLength = packet.Length - 40;
        packet[4] = (byte)(ipv6PayloadLength >> 8);
        packet[5] = (byte)ipv6PayloadLength;
        packet[6] = atomicFragmentHeader ? (byte)44 : (byte)17;
        packet[7] = 64;
        IPAddress.Parse("2001:db8::121").GetAddressBytes().CopyTo(packet, 8);
        IPAddress.Parse("fd00::66").GetAddressBytes().CopyTo(packet, 24);
        int udpOffset = 40 + extraHeader;
        if (atomicFragmentHeader)
            packet[40] = 17; // Atomic Fragment header; fully present but excluded.
        packet[udpOffset] = 0xbb; // source UDP/48000
        packet[udpOffset + 1] = 0x80;
        packet[udpOffset + 2] = 0xba; // destination UDP/47808
        packet[udpOffset + 3] = 0xc0;
        packet[udpOffset + 4] = (byte)((payload.Length + 8) >> 8);
        packet[udpOffset + 5] = (byte)(payload.Length + 8);
        payload.CopyTo(packet, udpOffset + 8);
        return Assert.IsType<TrafficRecord>(new PacketHandler().ParseFrame(
            packet, (PacketDotNet.LinkLayers)12));
    }

    [Fact]
    public void AnnexJIpv4BvlcFramesCarriedOverIpv6AreNotTrustedAsBacnetIp()
    {
        var dcc = BacnetDeviceCommunicationControlInspectorTests.Request();
        Assert.False(ParseIpv6Datagram(dcc, atomicFragmentHeader: false).BacnetDeviceCommunicationDisableObserved);
        Assert.False(ParseIpv6Datagram(dcc, atomicFragmentHeader: true).BacnetDeviceCommunicationDisableObserved);
        var write = BacnetWritePropertyInspectorTests.Request();
        Assert.False(ParseIpv6Datagram(write, atomicFragmentHeader: false).BacnetWritePropertyRequestObserved);
    }

    [Fact]
    public async Task InboundDisableRequestIsCaptureProvenAndOnlyShadowed()
    {
        var rec = BacnetWritePrecisionTests.Parse(
            BacnetDeviceCommunicationControlInspectorTests.Request(),
            sourceOverride: "203.0.113.121");
        Assert.True(rec.BacnetDeviceCommunicationDisableObserved);
        Assert.False(rec.BacnetWritePropertyRequestObserved);
        Assert.Equal("bacnet.devicecommunicationcontrol.disable", rec.ApplicationProtocol);
        var rule = new R486_BACnetDeviceCommunicationControlRule();
        Assert.Equal(86, rule.PrecisionProfile.MinimumConfidence);
        Assert.True(RulePrecisionCatalog.Validate("R486", rec).CanEvaluate);
        var result = await rule.EvaluateAsync(
            new RuleEvaluationContext(rec, Sensitivity.Balanced, DateTime.UtcNow));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal(DetectionSuppressionStatus.Shadowed, evt.SuppressionStatus);
        Assert.DoesNotContain("password", evt.Evidence ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SameUdpServicePortsCarryRealDccRequestNotAResponse()
    {
        var rec = BacnetWritePrecisionTests.Parse(
            BacnetDeviceCommunicationControlInspectorTests.Request(disableState: 1),
            sourceOverride: "203.0.113.122", sameServicePort: true);
        Assert.True(rec.BacnetDeviceCommunicationDisableObserved);
        var result = await new R486_BACnetDeviceCommunicationControlRule().EvaluateAsync(
            new RuleEvaluationContext(rec, Sensitivity.Balanced, DateTime.UtcNow));
        Assert.Equal(DetectionSuppressionStatus.Shadowed, Assert.Single(result.Events).SuppressionStatus);
    }

    [Fact]
    public async Task EnableReadPropertyWrongPortIncompleteCaptureAndInternalNetworkAreNoMatch()
    {
        var invalid = new[]
        {
            BacnetWritePrecisionTests.Parse(BacnetDeviceCommunicationControlInspectorTests.Request(disableState: 0), sourceOverride: "203.0.113.123"),
            BacnetWritePrecisionTests.Parse(BacnetDeviceCommunicationControlInspectorTests.Request(service: 0x0c), sourceOverride: "203.0.113.124"),
            BacnetWritePrecisionTests.Parse(BacnetDeviceCommunicationControlInspectorTests.Request(service: 0x0f), sourceOverride: "203.0.113.129"),
            BacnetWritePrecisionTests.Parse(BacnetDeviceCommunicationControlInspectorTests.Request(), reverse: true),
            BacnetWritePrecisionTests.Parse(BacnetDeviceCommunicationControlInspectorTests.Request(), declaredLengthExtra: 1, sourceOverride: "203.0.113.125")
        };
        var rule = new R486_BACnetDeviceCommunicationControlRule();
        foreach (var rec in invalid)
        {
            Assert.False(rec.BacnetDeviceCommunicationDisableObserved);
            Assert.False((await rule.EvaluateAsync(new RuleEvaluationContext(
                rec, Sensitivity.Balanced, DateTime.UtcNow))).Matched);
        }
        var internalOnly = BacnetWritePrecisionTests.Parse(
            BacnetDeviceCommunicationControlInspectorTests.Request(), privateSource: true);
        Assert.True(internalOnly.BacnetDeviceCommunicationDisableObserved);
        Assert.False((await rule.EvaluateAsync(new RuleEvaluationContext(
            internalOnly, Sensitivity.Balanced, DateTime.UtcNow))).Matched);
    }

    [Fact]
    public void Ipv4FragmentAndUdpIpDeclaredLengthDisagreementFailClosed()
    {
        var payload = BacnetDeviceCommunicationControlInspectorTests.Request();
        var raw = new byte[28 + payload.Length];
        raw[0] = 0x45;
        raw[2] = (byte)(raw.Length >> 8);
        raw[3] = (byte)raw.Length;
        raw[8] = 64;
        raw[9] = 17;
        IPAddress.Parse("203.0.113.130").GetAddressBytes().CopyTo(raw, 12);
        IPAddress.Parse("10.20.0.66").GetAddressBytes().CopyTo(raw, 16);
        raw[20] = 0xbb; raw[21] = 0x80; // UDP/48000
        raw[22] = 0xba; raw[23] = 0xc0; // UDP/47808
        raw[24] = (byte)((payload.Length + 8) >> 8);
        raw[25] = (byte)(payload.Length + 8);
        payload.CopyTo(raw, 28);

        var link = (PacketDotNet.LinkLayers)12;
        raw[6] = 0x20; // more IPv4 fragments, no assembled UDP request
        Assert.Null(new PacketHandler().ParseFrame(raw, link));
        raw[6] = 0;
        raw[25]--; // UDP declares a byte less than IP payload
        var record = Assert.IsType<TrafficRecord>(new PacketHandler().ParseFrame(raw, link));
        Assert.False(record.BacnetDeviceCommunicationDisableObserved);
    }

    [Fact]
    public async Task JsonAndTextCannotForgeDccCaptureFlag()
    {
        var claimed = JsonSerializer.Deserialize<TrafficRecord>(
            "{\"Source\":\"203.0.113.126\",\"Destination\":\"10.20.0.66\",\"IsUdp\":true,\"DestinationPort\":47808,\"ApplicationProtocol\":\"bacnet.devicecommunicationcontrol.disable\",\"BacnetDeviceCommunicationDisableObserved\":true,\"Info\":\"BACnet DeviceCommunicationControl DISABLE\"}");
        Assert.NotNull(claimed);
        Assert.False(claimed!.BacnetDeviceCommunicationDisableObserved);
        var rule = new R486_BACnetDeviceCommunicationControlRule();
        Assert.False(RulePrecisionCatalog.Validate("R486", claimed).CanEvaluate);
        Assert.False((await rule.EvaluateAsync(new RuleEvaluationContext(
            claimed, Sensitivity.Balanced, DateTime.UtcNow))).Matched);
    }

    [Fact]
    public async Task DuplicateDccAttemptUsesSuppressedMatchAndEmitsNoEvent()
    {
        var now = DateTime.UtcNow;
        var rule = new R486_BACnetDeviceCommunicationControlRule();
        var first = await rule.EvaluateAsync(new RuleEvaluationContext(
            BacnetWritePrecisionTests.Parse(BacnetDeviceCommunicationControlInspectorTests.Request(), sourceOverride: "203.0.113.127"),
            Sensitivity.Balanced, now));
        var second = await rule.EvaluateAsync(new RuleEvaluationContext(
            BacnetWritePrecisionTests.Parse(BacnetDeviceCommunicationControlInspectorTests.Request(), sourceOverride: "203.0.113.127"),
            Sensitivity.Balanced, now.AddSeconds(5)));
        Assert.Equal(DetectionSuppressionStatus.Shadowed, Assert.Single(first.Events).SuppressionStatus);
        Assert.True(second.Matched);
        Assert.True(second.Suppressed);
        Assert.Empty(second.Events);
    }

    [Fact]
    public async Task EnginePreparationPreservesR486ShadowDisposition()
    {
        var rule = new R486_BACnetDeviceCommunicationControlRule();
        var record = BacnetWritePrecisionTests.Parse(
            BacnetDeviceCommunicationControlInspectorTests.Request(), sourceOverride: "203.0.113.128");
        var result = await rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, DateTime.UtcNow));
        var evt = Assert.Single(result.Events);
        var preparation = typeof(RuleEngine).GetMethod("PrepareDetectionEvent",
            BindingFlags.Static | BindingFlags.NonPublic);
        Assert.NotNull(preparation);
        preparation!.Invoke(null, new object[] {
            evt, rule.Descriptor, record, Sensitivity.Balanced, DateTime.UtcNow
        });
        Assert.Equal(DetectionSuppressionStatus.Shadowed, evt.SuppressionStatus);
    }
}
