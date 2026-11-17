// SPDX-License-Identifier: MIT
using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Execution;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using PacketDotNet;
using Xunit;

namespace Carthago.Tests;

public sealed class R463CaptureBoundBurstTests
{
    private static readonly DateTime Epoch = new(2026, 11, 17, 10, 0, 0, DateTimeKind.Utc);

    private static TrafficRecord ObservedGratuitousArp(
        string ip = "192.168.50.10", string mac = "021122334455")
    {
        var address = IPAddress.Parse(ip);
        var frame = NpcapArpDiscovery.BuildRequest(
            PhysicalAddress.Parse(mac), address, address);
        var observed = new PacketHandler().ParseFrame(frame, LinkLayers.Ethernet);
        return Assert.IsType<TrafficRecord>(observed);
    }

    private static Task<RuleEvaluationResult> Eval(
        R463_ARPGratuitousStormRule rule, TrafficRecord record, DateTime at)
        => rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, at)).AsTask();

    [Fact]
    public async Task SixteenDistinctCaptureDecodedAnnouncementsMatchOnlyInShadow()
    {
        var rule = new R463_ARPGratuitousStormRule();
        for (var i = 0; i < 15; i++)
            Assert.False((await Eval(rule, ObservedGratuitousArp(),
                Epoch.AddSeconds(i))).Matched);
        var result = await Eval(rule, ObservedGratuitousArp(), Epoch.AddSeconds(15));
        Assert.True(result.Matched);
        Assert.False(result.Suppressed);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("02:11:22:33:44:55", evt.Evidence ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains("02:11:22:33:44:55", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(76, rule.PrecisionProfile.MinimumConfidence);
        Assert.Equal(16, rule.PrecisionProfile.Threshold);
    }

    [Fact]
    public async Task NormalArpRequestAndImportableTextAreNotProofOfGratuitousArp()
    {
        var rule = new R463_ARPGratuitousStormRule();
        var normal = NpcapArpDiscovery.BuildRequest(
            PhysicalAddress.Parse("021122334455"),
            IPAddress.Parse("192.168.50.10"), IPAddress.Parse("192.168.50.11"));
        var parsed = Assert.IsType<TrafficRecord>(
            new PacketHandler().ParseFrame(normal, LinkLayers.Ethernet));
        Assert.False((await Eval(rule, parsed, Epoch)).Matched);
        for (var i = 0; i < 20; i++)
        {
            var invented = new TrafficRecord
            {
                Source = "192.168.50.10", Destination = "192.168.50.10",
                Protocol = "ARP", ProtocolVersion = "ARP/IPv4",
                ApplicationProtocol = "ARP",
                MacSource = "02:11:22:33:44:55",
                MacDestination = "FF:FF:FF:FF:FF:FF",
                Info = "gratuitous ARP storm",
            };
            Assert.False((await Eval(rule, invented, Epoch.AddSeconds(i))).Matched);
        }
    }

    [Fact]
    public async Task EthernetSourceMacMismatchAndUnicastFrameFailClosed()
    {
        var rule = new R463_ARPGratuitousStormRule();
        for (var i = 0; i < 20; i++)
        {
            var frame = NpcapArpDiscovery.BuildRequest(
                PhysicalAddress.Parse("021122334455"),
                IPAddress.Parse("192.168.50.10"), IPAddress.Parse("192.168.50.10"));
            frame[6] ^= 0x01; // Ethernet source no longer matches ARP sender MAC
            var mismatch = Assert.IsType<TrafficRecord>(
                new PacketHandler().ParseFrame(frame, LinkLayers.Ethernet));
            Assert.False((await Eval(rule, mismatch, Epoch.AddSeconds(i))).Matched);

            var unicast = NpcapArpDiscovery.BuildRequest(
                PhysicalAddress.Parse("021122334455"),
                IPAddress.Parse("192.168.50.10"), IPAddress.Parse("192.168.50.10"));
            unicast[0] = 0x02; // No longer Ethernet broadcast
            var record = Assert.IsType<TrafficRecord>(
                new PacketHandler().ParseFrame(unicast, LinkLayers.Ethernet));
            Assert.False((await Eval(rule, record, Epoch.AddSeconds(i))).Matched);
        }
    }

    [Fact]
    public async Task ReplayedPacketIdentityNeverInflatesWindow()
    {
        var rule = new R463_ARPGratuitousStormRule();
        var record = ObservedGratuitousArp();
        for (var i = 0; i < 30; i++)
            Assert.False((await Eval(rule, record, Epoch.AddSeconds(i))).Matched);
        for (var i = 0; i < 14; i++)
            Assert.False((await Eval(rule, ObservedGratuitousArp(),
                Epoch.AddSeconds(30 + i))).Matched);
        Assert.True((await Eval(rule, ObservedGratuitousArp(), Epoch.AddSeconds(44))).Matched);
    }

    [Fact]
    public async Task IndependentMacAndHostStreamsCannotCombineIntoStorm()
    {
        var rule = new R463_ARPGratuitousStormRule();
        for (var i = 0; i < 15; i++)
        {
            Assert.False((await Eval(rule, ObservedGratuitousArp(),
                Epoch.AddSeconds(i))).Matched);
            Assert.False((await Eval(rule,
                ObservedGratuitousArp("192.168.50.10", "021122334466"),
                Epoch.AddSeconds(i))).Matched);
            Assert.False((await Eval(rule,
                ObservedGratuitousArp("192.168.50.11", "021122334477"),
                Epoch.AddSeconds(i))).Matched);
        }
        Assert.True((await Eval(rule, ObservedGratuitousArp(), Epoch.AddSeconds(15))).Matched);
    }

    [Fact]
    public async Task ExpiredAndOutOfOrderFramesCannotCompleteBurst()
    {
        var rule = new R463_ARPGratuitousStormRule();
        for (var i = 0; i < 15; i++)
            Assert.False((await Eval(rule, ObservedGratuitousArp(),
                Epoch.AddSeconds(i))).Matched);
        Assert.False((await Eval(rule, ObservedGratuitousArp(),
            Epoch.AddSeconds(1))).Matched); // stale relative to last observed frame
        Assert.False((await Eval(rule, ObservedGratuitousArp(),
            Epoch.AddMinutes(2))).Matched); // previous bucket expired
    }

    [Fact]
    public async Task RepeatStormIsSuppressedDuringCooldown()
    {
        var rule = new R463_ARPGratuitousStormRule();
        RuleEvaluationResult? result = null;
        for (var i = 0; i < 16; i++)
            result = await Eval(rule, ObservedGratuitousArp(), Epoch.AddSeconds(i));
        Assert.True(result!.Matched);
        result = await Eval(rule, ObservedGratuitousArp(), Epoch.AddSeconds(16));
        Assert.True(result.Matched);
        Assert.True(result.Suppressed);
    }

    [Fact]
    public async Task UnsupportedTransportAndNonPrivateSourceCannotPass()
    {
        var rule = new R463_ARPGratuitousStormRule();
        for (var i = 0; i < 18; i++)
        {
            var spoofedTransport = ObservedGratuitousArp();
            spoofedTransport.IsTcp = true;
            Assert.False((await Eval(rule, spoofedTransport,
                Epoch.AddSeconds(i))).Matched);

            var publicSource = ObservedGratuitousArp("198.51.100.15");
            Assert.False((await Eval(rule, publicSource,
                Epoch.AddSeconds(i))).Matched);
        }
    }

    [Fact]
    public void CaptureOriginArpIsSelectableAndDoesNotRequireDnsOrPayload()
    {
        var rule = new R463_ARPGratuitousStormRule();
        var record = ObservedGratuitousArp();
        Assert.True(record.ArpSenderMacMatchesFrame);
        var plan = new RuleCandidateSelector().CreatePlan(
            new IDetectionRule[] { rule }, record);
        Assert.True(Assert.Single(plan.Entries).ShouldEvaluate);
        Assert.DoesNotContain(RuleTelemetryKind.Dns, rule.PrecisionProfile.RequiredTelemetry);
        Assert.DoesNotContain(RuleTelemetryKind.Payload, rule.PrecisionProfile.RequiredTelemetry);
        Assert.True(RuleTelemetryValidator.Validate(rule, record).CanRunSafely);
    }
}
