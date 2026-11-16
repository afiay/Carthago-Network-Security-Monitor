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
            var smbEvent = Assert.Single(System.Linq.Enumerable.Where(
                RuleEngine.Evaluate(smb, Sensitivity.Balanced), e => e.RuleId == "R026"));

            // Replay the same real FTP packet after two independent emissions.
            // Neither repeated packet evaluation nor repeated FTP detections may
            // inflate the retained host/rule cardinality into a third family.
            for (var replay = 0; replay < 3; replay++)
            {
                Assert.DoesNotContain(RuleEngine.Evaluate(ftp, Sensitivity.Balanced),
                    e => e.RuleId == "R272");
                var replayAt = DateTime.UtcNow;
                var replayContext = RuleEvaluationContext.CreateForEngine(ftp,
                    Sensitivity.Balanced, replayAt, RuleEngineHealthSnapshot.Empty(replayAt));
                Assert.Single(System.Linq.Enumerable.Where(
                    replayContext.GetR272Signals(), signal => signal.RuleId == "R014"));
                Assert.False((await new R272_MultiSignalRuleStackSurgeFromHostRule()
                    .EvaluateAsync(replayContext)).Matched);
            }

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
                dnsEmitted = System.Linq.Enumerable.Any(
                    RuleEngine.Evaluate(dns, Sensitivity.Balanced), e => e.RuleId == "R031");
                // Stop at the first qualifying DNS emission. Subsequent packets
                // could consume the engine-owned R272 cooldown before the probe.
                if (dnsEmitted) break;
            }
            Assert.True(dnsEmitted, "The DNS producer must actually emit R031.");

            var other = Packet("10.214.1.99", "10.214.1.21", 443);
            Assert.DoesNotContain(RuleEngine.Evaluate(other, Sensitivity.Balanced), e => e.RuleId == "R272");

            // Evaluate the real detector against the engine-owned snapshot,
            // independently of whether an earlier packet consumed alert cooldown.
            var probe = Packet(host, "10.214.1.21", 443);
            probe.ProcessName = null;
            probe.ProcessId = 0;
            probe.Info = null;
            // R272 correlates emitted families, not TLS. A plain TCP probe
            // must survive the default selector and required telemetry gate.
            var selectedRule = new R272_MultiSignalRuleStackSurgeFromHostRule();
            var plan = new Carthago.Engine.Rules.Execution.RuleCandidateSelector()
                .CreatePlan(new IDetectionRule[] { selectedRule }, probe);
            Assert.True(plan.SelectedCount == 1);
            Assert.True(RuleTelemetryValidator.Validate(selectedRule, probe).CanRunSafely);
            // R272 is ShadowFirst in production tuning, independently of its
            // detector precision profile. Exercise actual alert delivery only in
            // the explicit Research profile; never promote production defaults.
            Assert.Equal(RuleMode.Shadow,
                Carthago.Engine.Rules.Tuning.RuleTuningCatalog.ResolveProfileMode(
                    "SmallBusiness", selectedRule.Descriptor));
            Assert.Equal(RuleMode.Alert,
                Carthago.Engine.Rules.Tuning.RuleTuningCatalog.ResolveProfileMode(
                    "Research", selectedRule.Descriptor));
            var cfg = typeof(RuleEngine).GetField("_cfg",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!
                .GetValue(null)!;
            var profileProperty = cfg.GetType().GetProperty("Profile")!;
            var previousProfile = profileProperty.GetValue(cfg);
            try
            {
                profileProperty.SetValue(cfg, "Research");
                var engineEvent = Assert.Single(System.Linq.Enumerable.Where(
                    RuleEngine.Evaluate(probe, Sensitivity.Balanced), e => e.RuleId == "R272"));
                Assert.True(engineEvent.ConfidenceScore >= 0.82);
                Assert.DoesNotContain(RuleEngine.Evaluate(probe, Sensitivity.Balanced),
                    e => e.RuleId == "R272");
            }
            finally { profileProperty.SetValue(cfg, previousProfile); }

            var now = DateTime.UtcNow;
            var context = RuleEvaluationContext.CreateForEngine(probe, Sensitivity.Balanced,
                now, RuleEngineHealthSnapshot.Empty(now));
            var result = await new R272_MultiSignalRuleStackSurgeFromHostRule()
                .EvaluateAsync(context);
            Assert.True(result.Matched);
            Assert.NotEmpty(result.Events);
            Assert.All(result.Events, e => Assert.True(e.ConfidenceScore >= 0.82));

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
            var ingest = typeof(RuleEngine).GetMethod("RecordR272EmittedSignal",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            Assert.NotNull(ingest);
            var descriptor = System.Linq.Enumerable.Single(
                Carthago.Engine.Rules.Catalog.RuleRegistry.CreateDefaultRules(),
                rule => rule.Descriptor.RuleId == "R014").Descriptor;
            // Mapped IPv6 and IPv4 refer to the same producer host.
            var mapped = Packet("::ffff:" + host, "10.214.1.21", 443);
            mapped.IpVersion = 6;
            var mappedContext = RuleEvaluationContext.CreateForEngine(mapped, Sensitivity.Balanced,
                now, RuleEngineHealthSnapshot.Empty(now));
            Assert.True((await new R272_MultiSignalRuleStackSurgeFromHostRule()
                .EvaluateAsync(mappedContext)).Matched);

            // Exercise the same detector instance: canonical aliases share cooldown.
            var cooldownRule = new R272_MultiSignalRuleStackSurgeFromHostRule();
            // Cooldown is shared across instances; the engine already emitted
            // for this canonical host. Suppression is a matched event, not NoMatch.
            var canonicalRepeat = await cooldownRule.EvaluateAsync(context);
            var aliasRepeat = await cooldownRule.EvaluateAsync(mappedContext);
            Assert.True(canonicalRepeat.Matched);
            Assert.True(aliasRepeat.Matched);
            Assert.Equal(DetectionSuppressionStatus.Suppressed,
                Assert.Single(canonicalRepeat.Events).SuppressionStatus);
            Assert.Equal(DetectionSuppressionStatus.Suppressed,
                Assert.Single(aliasRepeat.Events).SuppressionStatus);

            probe.Source = "10.214.1.99";
            Assert.False((await new R272_MultiSignalRuleStackSurgeFromHostRule()
                .EvaluateAsync(context)).Matched);
            probe.Source = host;

            RuleEngine.ResetRuntimeStateForReplay();
            var reset = RuleEvaluationContext.CreateForEngine(probe, Sensitivity.Balanced,
                now, RuleEngineHealthSnapshot.Empty(now));
            Assert.False((await new R272_MultiSignalRuleStackSurgeFromHostRule()
                .EvaluateAsync(reset)).Matched);

            // Defense in depth: the producer must reject a non-emitted policy
            // disposition even if a future caller bypasses the emission gate.
            var originalStatus = ftpEvent.SuppressionStatus;
            try
            {
                foreach (var status in new[] { DetectionSuppressionStatus.Suppressed,
                    DetectionSuppressionStatus.Shadowed })
                {
                    ftpEvent.SuppressionStatus = status;
                    ingest!.Invoke(null, new object[] { ftpEvent, descriptor, now });
                    Assert.Empty(RuleEngine.SnapshotR272Signals(host, now));
                }
            }
            finally { ftpEvent.SuppressionStatus = originalStatus; }
            ingest!.Invoke(null, new object[] { ftpEvent, descriptor, now });
            Assert.Contains(RuleEngine.SnapshotR272Signals(host, now), s => s.RuleId == "R014");
            RuleEngine.ResetRuntimeStateForReplay();

            // Non-unicast source addresses cannot identify a correlated host.
            var originalSource = ftpEvent.SourceIp;
            try
            {
                foreach (var invalidSource in new[] { "255.255.255.255", "224.0.0.1",
                    "::ffff:224.0.0.1", "ff02::1" })
                {
                    ftpEvent.SourceIp = invalidSource;
                    ingest!.Invoke(null, new object[] { ftpEvent, descriptor, now });
                    Assert.Empty(RuleEngine.SnapshotR272Signals(invalidSource, now));
                }
            }
            finally { ftpEvent.SourceIp = originalSource; }
            ingest!.Invoke(null, new object[] { ftpEvent, descriptor, now });
            Assert.Contains(RuleEngine.SnapshotR272Signals(host, now), s => s.RuleId == "R014");
            RuleEngine.ResetRuntimeStateForReplay();

            // Isolate the exact identity from later legitimate FTP emissions.
            // The live host/rule slot may have been refreshed by a different event.
            RuleEngine.ResetRuntimeStateForReplay();
            var originalAt = ftpEvent.TimestampUtc;
            ingest!.Invoke(null, new object[] { ftpEvent, descriptor, originalAt });
            var exact = originalAt.AddMinutes(10);
            Assert.Contains(RuleEngine.SnapshotR272Signals(host, exact), x => x.RuleId == "R014");
            ingest.Invoke(null, new object[] { ftpEvent, descriptor, originalAt.AddMinutes(1) });
            Assert.DoesNotContain(RuleEngine.SnapshotR272Signals(host, exact.AddTicks(1)),
                x => x.RuleId == "R014");
            RuleEngine.ResetRuntimeStateForReplay();

            // A newer real emission replaces the host/rule slot, but must not
            // erase the original identity while it is still in the retention window.
            var replacement = Assert.Single(System.Linq.Enumerable.Where(
                RuleEngine.Evaluate(ftp, Sensitivity.Balanced), e => e.RuleId == "R014"));
            Assert.NotEqual(ftpEvent.EventId, replacement.EventId);
            RuleEngine.ResetRuntimeStateForReplay();
            ingest.Invoke(null, new object[] { ftpEvent, descriptor, now });
            ingest.Invoke(null, new object[] { replacement, descriptor, now.AddMinutes(1) });
            ingest.Invoke(null, new object[] { ftpEvent, descriptor, now.AddMinutes(2) });
            Assert.Contains(RuleEngine.SnapshotR272Signals(host, now.AddMinutes(11)), s => s.RuleId == "R014");
            Assert.DoesNotContain(RuleEngine.SnapshotR272Signals(host, now.AddMinutes(11).AddTicks(1)), s => s.RuleId == "R014");
            RuleEngine.ResetRuntimeStateForReplay();

            // Replay actual emitted identities in reverse timestamp order after reset.
            // A stale event must not resurrect evidence outside the producer watermark.
            var smbDescriptor = System.Linq.Enumerable.Single(
                Carthago.Engine.Rules.Catalog.RuleRegistry.CreateDefaultRules(),
                rule => rule.Descriptor.RuleId == "R026").Descriptor;
            var latest = now.AddMinutes(20);
            ingest.Invoke(null, new object[] { smbEvent, smbDescriptor, latest });
            ingest.Invoke(null, new object[] { ftpEvent, descriptor, latest.AddMinutes(-10).AddTicks(-1) });
            Assert.DoesNotContain(RuleEngine.SnapshotR272Signals(host, latest), s => s.RuleId == "R014");
            Assert.Contains(RuleEngine.SnapshotR272Signals(host, latest), s => s.RuleId == "R026");
            // The exact boundary is admissible, including for delayed arrivals.
            ingest.Invoke(null, new object[] { ftpEvent, descriptor, latest.AddMinutes(-10) });
            Assert.Contains(RuleEngine.SnapshotR272Signals(host, latest), s => s.RuleId == "R014");
            Assert.DoesNotContain(RuleEngine.SnapshotR272Signals(host, latest.AddTicks(1)), s => s.RuleId == "R014");
            var ordered = RuleEvaluationContext.CreateForEngine(probe, Sensitivity.Balanced,
                latest, RuleEngineHealthSnapshot.Empty(latest));
            Assert.False((await new R272_MultiSignalRuleStackSurgeFromHostRule()
                .EvaluateAsync(ordered)).Matched);
            RuleEngine.ResetRuntimeStateForReplay();
            ingest.Invoke(null, new object[] { ftpEvent, descriptor, now });
            Assert.Contains(RuleEngine.SnapshotR272Signals(host, now), s => s.RuleId == "R014");

            // Delayed observations must expire by timestamp, not insertion order.
            RuleEngine.ResetRuntimeStateForReplay();
            ingest.Invoke(null, new object[] { smbEvent, smbDescriptor, now.AddMinutes(5) });
            ingest.Invoke(null, new object[] { ftpEvent, descriptor, now });
            ingest.Invoke(null, new object[] { replacement, descriptor, now.AddMinutes(11) });
            Assert.Contains(RuleEngine.SnapshotR272Signals(host, now.AddMinutes(11)), s => s.RuleId == "R026");
            Assert.Contains(RuleEngine.SnapshotR272Signals(host, now.AddMinutes(11)), s => s.RuleId == "R014");
            // The expired FTP identity can be admitted again; the retained SMB
            // identity cannot refresh its observation or advance the watermark.
            ingest.Invoke(null, new object[] { ftpEvent, descriptor, now.AddMinutes(12) });
            ingest.Invoke(null, new object[] { smbEvent, smbDescriptor, now.AddMinutes(13) });
            Assert.Contains(RuleEngine.SnapshotR272Signals(host, now.AddMinutes(22)), s => s.RuleId == "R014");
            Assert.DoesNotContain(RuleEngine.SnapshotR272Signals(host, now.AddMinutes(16)), s => s.RuleId == "R026");

            // A retained identity cannot advance the global watermark, even
            // when replayed far into the future. The other real family must
            // remain available at its original observation time.
            RuleEngine.ResetRuntimeStateForReplay();
            ingest.Invoke(null, new object[] { ftpEvent, descriptor, now });
            ingest.Invoke(null, new object[] { smbEvent, smbDescriptor, now });
            ingest.Invoke(null, new object[] { ftpEvent, descriptor, now.AddHours(1) });
            Assert.Contains(RuleEngine.SnapshotR272Signals(host, now), x => x.RuleId == "R026");
            Assert.Contains(RuleEngine.SnapshotR272Signals(host, now), x => x.RuleId == "R014");
            Assert.Empty(RuleEngine.SnapshotR272Signals(host, now.AddHours(1)));

            // Capacity is a producer-state test, not synthetic detector evidence.
            // Populate only the identity indexes, never the correlation observations.
            RuleEngine.ResetRuntimeStateForReplay();
            var flags = System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static;
            var seen = (System.Collections.Generic.Dictionary<string, DateTime>)
                typeof(RuleEngine).GetField("R272SeenEvents", flags)!.GetValue(null)!;
            var expiry = (System.Collections.Generic.PriorityQueue<string, DateTime>)
                typeof(RuleEngine).GetField("R272SeenExpiry", flags)!.GetValue(null)!;
            var capacity = (int)typeof(RuleEngine).GetField("R272SeenCapacity", flags)!.GetRawConstantValue()!;
            for (var i = 0; i < capacity; i++)
            {
                var id = "capacity-fixture-" + i;
                seen.Add(id, now);
                expiry.Enqueue(id, now);
            }
            var fullAt = now.AddMinutes(10);
            ingest.Invoke(null, new object[] { ftpEvent, descriptor, fullAt });
            Assert.Equal(capacity, seen.Count);
            Assert.Equal(capacity, expiry.Count);
            Assert.Empty(RuleEngine.SnapshotR272Signals(host, fullAt));
            var fullContext = RuleEvaluationContext.CreateForEngine(probe, Sensitivity.Balanced,
                fullAt, RuleEngineHealthSnapshot.Empty(fullAt));
            Assert.False((await new R272_MultiSignalRuleStackSurgeFromHostRule()
                .EvaluateAsync(fullContext)).Matched);
            // One tick beyond the inclusive window frees all expired identities.
            var recoveredAt = fullAt.AddTicks(1);
            ingest.Invoke(null, new object[] { ftpEvent, descriptor, recoveredAt });
            Assert.Single(seen);
            Assert.Equal(1, expiry.Count);
            Assert.Contains(RuleEngine.SnapshotR272Signals(host, recoveredAt), s => s.RuleId == "R014");
            RuleEngine.ResetRuntimeStateForReplay();
            Assert.Empty(seen);
            Assert.Equal(0, expiry.Count);

            // Replay clocks at the representable lower bound must not throw or
            // manufacture a third family. Exercise the actual emitted identity.
            RuleEngine.ResetRuntimeStateForReplay();
            var early = DateTime.MinValue.AddMinutes(1);
            ingest.Invoke(null, new object[] { ftpEvent, descriptor, early });
            Assert.Contains(RuleEngine.SnapshotR272Signals(host, early), s => s.RuleId == "R014");
            Assert.Empty(RuleEngine.SnapshotR272Signals(host, DateTime.MinValue));
            Assert.Contains(RuleEngine.SnapshotR272Signals(host, early.AddMinutes(10)), s => s.RuleId == "R014");
            Assert.Empty(RuleEngine.SnapshotR272Signals(host, early.AddMinutes(10).AddTicks(1)));
        }
        finally { RuleEngine.ResetRuntimeStateForReplay(); }
    }

    [Fact] public void High_Confidence_Mode_And_Threshold_Preserved() {
        var p = new R272_MultiSignalRuleStackSurgeFromHostRule().PrecisionProfile;
        Assert.Equal(82, p.MinimumConfidence); Assert.Equal(3, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
