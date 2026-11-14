// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public sealed class R272AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch271275Context.Sample();
    private static async Task<bool> Hit(TrafficRecord r, double seconds = 0)
        => (await new R272_MultiSignalRuleStackSurgeFromHostRule()
            .EvaluateAsync(NetworkBatch271275Context.At(r, seconds))).Matched;
    [Fact] public async Task Packet_Info_Claiming_Three_Alerts_Is_Not_Correlation() {
        var r = Sample(); r.Info = "multi-signal rule stack surge three detections";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Three_Different_Packets_Are_Not_Three_Rule_Families() {
        var r = Sample(); var rule = new R272_MultiSignalRuleStackSurgeFromHostRule();
        for (var i = 0; i < 3; i++)
            Assert.False((await rule.EvaluateAsync(NetworkBatch271275Context.At(
                NetworkBatch271275Context.Copy(r), i))).Matched);
    }
    [Fact] public async Task Three_Different_Destinations_Are_Not_Alert_Correlation() {
        var r = Sample();
        for (var i = 0; i < 3; i++) {
            r.Destination = $"10.61.0.{i + 10}";
            Assert.False(await Hit(NetworkBatch271275Context.Copy(r), i));
        }
    }
    [Fact] public async Task Duplicate_Replay_Cannot_Create_Stack() {
        var r = Sample(); Assert.False(await Hit(r)); Assert.False(await Hit(r, 1));
    }
    [Fact] public async Task Out_Of_Order_Packets_Cannot_Create_Stack() {
        var r = Sample(); Assert.False(await Hit(r, 10)); Assert.False(await Hit(r, 2));
    }
    [Fact] public async Task Process_Name_Claim_Is_Not_Emitted_Rule_Event() {
        var r = Sample(); r.ProcessName = "R003_R016_R271.exe"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Host_Missing_Cannot_Create_Correlation() {
        var r = Sample(); r.Source = null; Assert.False(await Hit(r));
    }
    [Fact] public async Task Protocol_Contradiction_Is_Not_Correlation() {
        var r = Sample(); r.IsUdp = true; Assert.False(await Hit(r));
    }
    [Fact] public async Task Reputation_And_Feed_Text_Are_Not_Three_Alerts() {
        var r = Sample(); r.Info = "R003 R016 R271 all matched";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Synthetic_Alert_Count_In_Http_Uri_Is_Not_Trusted() {
        var r = Sample(); r.HttpUri = "/alerts?rules=R003,R016,R271";
        Assert.False(await Hit(r));
    }
    // Reuse GA-04 packet semantics, but correlate real post-policy emissions
    // from three distinct legacy categories on one source.
    [Fact]
    public async Task Engine_Emissions_Correlate_Only_On_The_Observed_Host()
    {
        RuleEngine.ResetRuntimeStateForReplay();
        try
        {
            const string host = "10.214.1.20";
            TrafficRecord Packet(string source, string destination, int port) => new()
            {
                Id = Guid.NewGuid(), Source = source, Destination = destination,
                IpVersion = 4, Protocol = "TCP", IsTcp = true, SourcePort = 50521,
                DestinationPort = port, Length = 100, ProcessName = "fixture-client.exe",
                ProcessId = 4242
            };
            var ftp = Packet(host, "10.214.1.21", 21);
            ftp.ApplicationService = "FTP";
            ftp.Info = "PASS synthetic-test-only-value";
            var ftpEvent = Assert.Single(System.Linq.Enumerable.Where(
                RuleEngine.Evaluate(ftp, Sensitivity.Balanced), e => e.RuleId == "R014"));

            var smb = Packet(host, "8.8.8.8", 445);
            smb.Flags = "SYN"; smb.TcpFlags = 2;
            Assert.Contains(RuleEngine.Evaluate(smb, Sensitivity.Balanced), e => e.RuleId == "R026");

            // Two actual emitted families must not satisfy the three-family threshold.
            var twoProbe = Packet(host, "10.214.1.21", 443);
            var twoAt = DateTime.UtcNow;
            var twoContext = RuleEvaluationContext.CreateForEngine(twoProbe,
                Sensitivity.Balanced, twoAt, RuleEngineHealthSnapshot.Empty(twoAt));
            Assert.Contains(twoContext.GetR272Signals(), signal => signal.RuleId == "R014");
            Assert.Contains(twoContext.GetR272Signals(), signal => signal.RuleId == "R026");
            Assert.False((await new R272_MultiSignalRuleStackSurgeFromHostRule()
                .EvaluateAsync(twoContext)).Matched);

            bool dnsEmitted = false;
            for (int i = 0; i < 15; i++)
            {
                var dns = Packet(host, "10.214.1.53", 53);
                dns.Protocol = "DNS"; dns.IsTcp = false; dns.IsUdp = true;
                dns.DnsQtype = "TXT"; dns.DnsQname = $"query{i}.synthetic.invalid";
                dns.DnsIsResponse = false;
                dnsEmitted |= System.Linq.Enumerable.Any(
                    RuleEngine.Evaluate(dns, Sensitivity.Balanced), e => e.RuleId == "R031");
            }
            Assert.True(dnsEmitted, "The DNS producer must actually emit R031.");

            var other = Packet("10.214.1.99", "10.214.1.21", 443);
            Assert.DoesNotContain(RuleEngine.Evaluate(other, Sensitivity.Balanced), e => e.RuleId == "R272");

            // Evaluate the real detector against the engine-owned snapshot,
            // independently of whether an earlier packet consumed alert cooldown.
            var probe = Packet(host, "10.214.1.21", 443);
            // Exercise selection, telemetry validation and final post-policy emission.
            var engineEvent = Assert.Single(System.Linq.Enumerable.Where(
                RuleEngine.Evaluate(probe, Sensitivity.Balanced), e => e.RuleId == "R272"));
            Assert.True(engineEvent.ConfidenceScore >= 82);
            Assert.DoesNotContain(RuleEngine.Evaluate(probe, Sensitivity.Balanced),
                e => e.RuleId == "R272");

            var now = DateTime.UtcNow;
            var context = RuleEvaluationContext.CreateForEngine(probe, Sensitivity.Balanced,
                now, RuleEngineHealthSnapshot.Empty(now));
            var result = await new R272_MultiSignalRuleStackSurgeFromHostRule()
                .EvaluateAsync(context);
            Assert.True(result.Matched);
            Assert.NotEmpty(result.Events);
            Assert.All(result.Events, e => Assert.True(e.ConfidenceScore >= 82));

            // A context captured before the DNS emission cannot gain evidence
            // retroactively, even though the live host now has three families.
            Assert.DoesNotContain(twoContext.GetR272Signals(), s => s.RuleId == "R031");
            Assert.False((await new R272_MultiSignalRuleStackSurgeFromHostRule()
                .EvaluateAsync(twoContext)).Matched);

            Assert.False((await new R272_MultiSignalRuleStackSurgeFromHostRule()
                .EvaluateAsync(new RuleEvaluationContext(probe, Sensitivity.Balanced, now))).Matched);

            // The snapshot is frozen at creation; future and expired observations
            // must not qualify even when the same host has emitted three families.
            foreach (var offset in new[] { TimeSpan.FromMinutes(-1), TimeSpan.FromMinutes(11) })
            {
                var at = now.Add(offset);
                var boundary = RuleEvaluationContext.CreateForEngine(probe, Sensitivity.Balanced,
                    at, RuleEngineHealthSnapshot.Empty(at));
                Assert.False((await new R272_MultiSignalRuleStackSurgeFromHostRule()
                .EvaluateAsync(boundary)).Matched);
            }
            // The actual emitted event timestamp defines the inclusive boundary.
            var exact = ftpEvent.TimestampUtc.AddMinutes(10);
            Assert.Contains(RuleEngine.SnapshotR272Signals(host, exact), s => s.RuleId == "R014");
            Assert.DoesNotContain(RuleEngine.SnapshotR272Signals(host, exact.AddTicks(1)),
                s => s.RuleId == "R014");

            // Mapped IPv6 and IPv4 refer to the same producer host.
            var mapped = Packet("::ffff:" + host, "10.214.1.21", 443);
            mapped.IpVersion = 6;
            var mappedContext = RuleEvaluationContext.CreateForEngine(mapped, Sensitivity.Balanced,
                now, RuleEngineHealthSnapshot.Empty(now));
            Assert.True((await new R272_MultiSignalRuleStackSurgeFromHostRule()
                .EvaluateAsync(mappedContext)).Matched);

            // Exercise the same detector instance: canonical aliases share cooldown.
            var cooldownRule = new R272_MultiSignalRuleStackSurgeFromHostRule();
            Assert.True((await cooldownRule.EvaluateAsync(context)).Matched);
            Assert.False((await cooldownRule.EvaluateAsync(mappedContext)).Matched);

            probe.Source = "10.214.1.99";
            Assert.False((await new R272_MultiSignalRuleStackSurgeFromHostRule()
                .EvaluateAsync(context)).Matched);
            probe.Source = host;

            RuleEngine.ResetRuntimeStateForReplay();
            var reset = RuleEvaluationContext.CreateForEngine(probe, Sensitivity.Balanced,
                now, RuleEngineHealthSnapshot.Empty(now));
            Assert.False((await new R272_MultiSignalRuleStackSurgeFromHostRule()
                .EvaluateAsync(reset)).Matched);
        }
        finally { RuleEngine.ResetRuntimeStateForReplay(); }
    }

    [Fact] public void High_Confidence_Mode_And_Threshold_Preserved() {
        var p = new R272_MultiSignalRuleStackSurgeFromHostRule().PrecisionProfile;
        Assert.Equal(82, p.MinimumConfidence); Assert.Equal(3, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
