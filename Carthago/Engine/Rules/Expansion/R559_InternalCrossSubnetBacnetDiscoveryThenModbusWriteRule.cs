// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R559_InternalCrossSubnetBacnetDiscoveryThenModbusWriteRule.cs
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Correlates internal BACnet Who-Is discovery with subsequent Modbus/TCP
    /// write request shapes from the same private source to two targets
    /// in distinct remote RFC1918 /24 networks. Neither identity nor write outcome
    /// is authenticated by the packet sensor.
    /// </summary>
    public sealed class R559_InternalCrossSubnetBacnetDiscoveryThenModbusWriteRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly TimeSpan ObservationWindow = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan PairWindow = TimeSpan.FromMinutes(2);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);
        private const int MaxSources = 1024;
        private const int MaxTargetsPerSource = 32;
        private const int MaxIdsPerSource = 128;

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R559",
            Name: "Internal Cross-Subnet BACnet Discovery Followed by Modbus Write Requests",
            Category: "IotOtAdvanced",
            Description: "One private IPv4 source sends BACnet Who-Is requests then Modbus write requests to targets in two distinct other private /24s; no control outcome is inferred.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R559.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R559",
            maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port" },
            evidenceFields: new[] { "ot.discovery", "ot.write", "matched_conditions", "count", "window_seconds", "pair_max_seconds" },
            positiveConditions: new[]
            {
                "The existing PacketHandler and OT wire classifier must identify an IPv4 UDP/47808 BACnet Who-Is-shaped datagram and a later IPv4 TCP/502 Modbus write-request shape.",
                "Both operations must share an exact RFC1918 IPv4 source and a target in a different private /24; each write must follow its discovery by at most 120 seconds.",
                "Two distinct remote RFC1918 destination /24 networks must complete this sequence within five minutes, with unique packet IDs and monotonic observation times."
            },
            negativeConditions: new[]
            {
                "Reject Modbus reads/responses, BACnet I-Am, generic port/Info claims, same-/24 commissioning, one-subnet retries, public sources/targets and mismatched pairs.",
                "Reject malformed/truncated framing, contradictory HTTP/DNS/TLS metadata, stale/out-of-order packets, duplicate IDs and encrypted or unsupported capture.",
                "Do not infer authenticated identity, target vulnerability, Modbus register values, accepted writes, process changes or exploitation."
            },
            minimumConfidence: 90,
            threshold: 2,
            window: ObservationWindow,
            cooldown: Cooldown,
            distinctBy: "private_source+two_distinct_remote_private_24_discovery_then_write_pairs",
            falsePositives: new[]
            {
                "Authorized routed building-automation gateways, cross-segment commissioning, diagnostics and maintenance can legitimately use both BACnet and Modbus.",
                "NAT, VPNs, spoofed UDP sources, missing TCP segments and one-sided capture can misattribute or conceal a sequence; approve engineering-host roles, target segments and maintenance windows before alert promotion."
            },
            tuningKnobs: new[] { "Mode", "ApprovedOtGateways", "ApprovedEngineeringHosts", "ApprovedMaintenanceWindows" },
            requiredTests: new[]
            {
                "real PacketHandler cross-subnet BACnet/Modbus producer-positive and read/I-Am negative",
                "same-subnet commissioning, same-remote-/24, mismatched source and destination negatives",
                "malformed/truncated, Info-only, spoofed metadata and privacy fail-closed",
                "duplicate, out-of-order, 120-second pair limit, five-minute window, bounded state, concurrency and cooldown",
                "candidate Shadow policy, confidence floor and unique registry registration"
            });

        private sealed class TargetObservation
        {
            internal DateTime DiscoveryAt;
            internal bool Completed;
            internal DateTime CompletedAt;
        }

        private sealed class SourceBucket
        {
            internal readonly Dictionary<string, TargetObservation> Targets = new(StringComparer.Ordinal);
            internal readonly Dictionary<Guid, DateTime> SeenIds = new();
            internal DateTime Latest;
            internal DateTime? LastEmission;
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, SourceBucket> _sources = new(StringComparer.Ordinal);

        public R559_InternalCrossSubnetBacnetDiscoveryThenModbusWriteRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (record.Id == Guid.Empty || record.IpVersion != 4
                || record.IsQuic || record.Sni != null || record.TlsVersion != null
                || record.Alpn != null || record.HttpHost != null || record.HttpUri != null
                || record.HttpMethod != null || record.HttpRequestHeaders != null
                || record.DnsQname != null || record.DnsQtype != null || record.DnsAnswers != null
                || record.DnsRcode != null)
                return NoMatch();

            var discovery = NetworkBatch241245Evidence.Bacnet(record, out var operation)
                && operation == "whois"
                && record.SourcePort == 47808 && record.DestinationPort == 47808
                && record.L4Len is >= 8 and <= 1476;
            var write = !discovery && NetworkBatch236240Evidence.ModbusWrite(record)
                && record.SourcePort is >= 1024 and <= 65535 and not 502
                && record.DestinationPort == 502
                && record.L4Len is >= 12 and <= 260;

            if (!discovery && !write
                || !TryPrivateIpv4(record.Source, out var sourceIp)
                || !TryPrivateIpv4(record.Destination, out var privateIp)
                || SameSubnet24(sourceIp, privateIp))
                return NoMatch();

            if (!TryObserve(sourceIp, privateIp, discovery, record.Id,
                context.TimestampUtc, out var count, out var suppressed))
                return NoMatch();
            if (suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            // Never persist packet Info, raw protocol payload, device identity,
            // Modbus register addresses or values, credentials or headers.
            var evidence = new[]
            {
                new DetectionEvidenceItem("ot.discovery", "bacnet.whois", "bounded-packet-classifier"),
                new DetectionEvidenceItem("ot.write", "modbus.write.request", "bounded-packet-classifier"),
                new DetectionEvidenceItem("matched_conditions", "same_private_source,same_remote_private_target,discovery_before_write,two_distinct_remote_24s", "rule"),
                new DetectionEvidenceItem("count", count.ToString(CultureInfo.InvariantCulture), "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule"),
                new DetectionEvidenceItem("pair_max_seconds", "120", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "Internal cross-subnet BACnet discovery preceded Modbus write requests in two remote private /24s (outcomes unverified)",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.46, "wire-classified-bacnet-and-modbus-request-shapes");
                    confidence.AddEvidence(0.28, "same-private-source-and-remote-target-pairs");
                    confidence.AddCorrelation(0.22, "two-ordered-cross-protocol-remote-subnet-pairs");
                }, count: count, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        private bool TryObserve(string sourceIp, string privateIp, bool discovery,
            Guid id, DateTime now, out int count, out bool suppressed)
        {
            count = 0;
            suppressed = false;
            lock (_gate)
            {
                if (!_sources.TryGetValue(sourceIp, out var bucket))
                {
                    if (!discovery)
                        return false;
                    if (_sources.Count >= MaxSources)
                    {
                        var stale = new List<string>();
                        foreach (var entry in _sources)
                            if (now >= entry.Value.Latest && now - entry.Value.Latest > Cooldown)
                                stale.Add(entry.Key);
                        foreach (var key in stale)
                            _sources.Remove(key);
                        if (_sources.Count >= MaxSources)
                            return false;
                    }
                    bucket = new SourceBucket { Latest = now };
                    _sources.Add(sourceIp, bucket);
                }

                if (now < bucket.Latest || bucket.SeenIds.ContainsKey(id))
                    return false;

                var expiredIds = new List<Guid>();
                foreach (var entry in bucket.SeenIds)
                    if (now >= entry.Value && now - entry.Value > ObservationWindow)
                        expiredIds.Add(entry.Key);
                foreach (var old in expiredIds)
                    bucket.SeenIds.Remove(old);

                var expiredTargets = new List<string>();
                foreach (var entry in bucket.Targets)
                {
                    var last = entry.Value.Completed ? entry.Value.CompletedAt : entry.Value.DiscoveryAt;
                    if (now >= last && now - last > ObservationWindow)
                        expiredTargets.Add(entry.Key);
                }
                foreach (var old in expiredTargets)
                    bucket.Targets.Remove(old);

                if (bucket.SeenIds.Count >= MaxIdsPerSource)
                    return false;

                if (discovery)
                {
                    if (!bucket.Targets.TryGetValue(privateIp, out var target))
                    {
                        if (bucket.Targets.Count >= MaxTargetsPerSource)
                            return false;
                        target = new TargetObservation();
                        bucket.Targets.Add(privateIp, target);
                    }
                    if (!target.Completed)
                        target.DiscoveryAt = now;
                    bucket.SeenIds.Add(id, now);
                    bucket.Latest = now;
                    return false;
                }

                if (!bucket.Targets.TryGetValue(privateIp, out var pending)
                    || pending.Completed || now <= pending.DiscoveryAt
                    || now - pending.DiscoveryAt > PairWindow)
                    return false;

                bucket.SeenIds.Add(id, now);
                bucket.Latest = now;
                pending.Completed = true;
                pending.CompletedAt = now;

                // Count completed remote networks, not hosts in one /24.
                var completedSubnets = new HashSet<string>(StringComparer.Ordinal);
                foreach (var entry in bucket.Targets)
                    if (entry.Value.Completed && now >= entry.Value.CompletedAt
                        && now - entry.Value.CompletedAt <= ObservationWindow)
                        completedSubnets.Add(Subnet24(entry.Key));
                count = completedSubnets.Count;

                if (count < 2)
                    return false;
                if (bucket.LastEmission.HasValue && now >= bucket.LastEmission.Value
                    && now - bucket.LastEmission.Value < Cooldown)
                {
                    suppressed = true;
                    return true;
                }
                bucket.LastEmission = now;
                return true;
            }
        }

        private static bool TryPrivateIpv4(string? address, out string normalized)
        {
            normalized = string.Empty;
            if (!IPAddress.TryParse(address, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork)
                return false;
            var b = ip.GetAddressBytes();
            if (!(b[0] == 10
                || b[0] == 172 && b[1] is >= 16 and <= 31
                || b[0] == 192 && b[1] == 168))
                return false;
            normalized = ip.ToString();
            return true;
        }

        private static bool SameSubnet24(string first, string second)
            => string.Equals(Subnet24(first), Subnet24(second), StringComparison.Ordinal);

        private static string Subnet24(string address)
        {
            // Only RFC1918 IPv4 addresses reach this method.
            var octets = IPAddress.Parse(address).GetAddressBytes();
            return $"{octets[0]}.{octets[1]}.{octets[2]}";
        }
    }
}
