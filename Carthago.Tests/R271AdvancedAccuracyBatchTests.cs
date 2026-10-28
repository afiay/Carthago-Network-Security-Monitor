// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public sealed class R271AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch271275Context.Sample();
    private static bool Overlap(TrafficRecord r) => NetworkBatch271275Context.Overlap(r);
    [Fact] public void Exact_Feed_And_Independent_Source_Reputation_Overlap_Contract()
        => Assert.True(Overlap(Sample()));
    [Fact] public void Feed_Must_Identify_Same_Source_IP() {
        var r = Sample(); Assert.False(NetworkBatch271275Context.Overlap(r,
            NetworkBatch271275Context.Feed("185.220.100.253")));
    }
    [Fact] public void Malicious_Flag_Must_Be_True() {
        var r = Sample(); r.ReputationIsMalicious = false; Assert.False(Overlap(r));
    }
    [Fact] public void Low_Reputation_Confidence_Does_Not_Corroborate() {
        var r = Sample(); r.ReputationScore = 20; Assert.False(Overlap(r));
    }
    [Fact] public void Insufficient_Independent_Reports_Reject() {
        var r = Sample(); r.ReputationReports = 1; Assert.False(Overlap(r));
    }
    [Fact] public void Stale_Reputation_Rejects() {
        var r = Sample(); r.ReputationLastSeen = NetworkBatch271275Context.Origin.AddDays(-40);
        Assert.False(Overlap(r));
    }
    [Fact] public void Stale_Threat_Feed_Snapshot_Rejects() {
        var r = Sample(); Assert.False(NetworkBatch271275Context.Overlap(r,
            built: new DateTimeOffset(NetworkBatch271275Context.Origin.AddDays(-3))));
    }
    [Fact] public void Feed_Without_Source_Provenance_Rejects() {
        var r = Sample(); var hit = new MatchInfo(IndicatorKind.IPv4, r.Source!, 95,
            Array.Empty<string>(), Array.Empty<string>());
        Assert.False(NetworkBatch271275Context.Overlap(r, hit));
    }
    [Fact] public void Outbound_Direction_Does_Not_Qualify() {
        var r = Sample(); r.Source = "10.61.0.10"; r.Destination = "185.220.100.254";
        Assert.False(Overlap(r));
    }
    [Fact] public void Contradictory_Transport_Rejects() {
        var r = Sample(); r.IsUdp = true; Assert.False(Overlap(r));
    }
    [Fact] public void Info_Spoof_Cannot_Create_Feed_Or_Reputation() {
        var r = Sample(); r.ReputationIsMalicious = null;
        r.Info = "IOC threat feed hit malicious reputation 99";
        Assert.False(Overlap(r));
    }
    [Fact] public void Reserved_Documentation_Address_Not_Public_Feed_Source() {
        var r = Sample(); r.Source = "198.51.100.254";
        Assert.False(NetworkBatch271275Context.Overlap(r,
            NetworkBatch271275Context.Feed("198.51.100.254")));
    }
    [Fact] public void Missing_IP_Version_Rejects() {
        var r = Sample(); r.IpVersion = null; Assert.False(Overlap(r));
    }
    [Fact] public void Critical_Confidence_Mode_And_Threshold_Preserved() {
        var p = new R271_ThreatFeedIocWithLowReputationOverlapRule().PrecisionProfile;
        Assert.Equal(88, p.MinimumConfidence); Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
