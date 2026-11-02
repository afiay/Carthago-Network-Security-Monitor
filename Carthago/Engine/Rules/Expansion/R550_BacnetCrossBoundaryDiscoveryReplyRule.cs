// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R550_BacnetCrossBoundaryDiscoveryReplyRule.cs
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Correlates public-to-private BACnet Who-Is-shaped datagrams with
    /// reverse-direction I-Am-shaped datagrams from two distinct private
    /// endpoints. This is a discovery exposure candidate, not authentication
    /// or proof that a device responded to a particular request.
    /// </summary>
    public sealed class R550_BacnetCrossBoundaryDiscoveryReplyRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly TimeSpan ObservationWindow = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan ReplyWindow = TimeSpan.FromSeconds(60);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);
        private const int MaxSources = 2048;
        private const int MaxTargetsPerSource = 64;
        private const int MaxIdsPerSource = 256;

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R550",
            Name: "BACnet Cross-Boundary Discovery Reply Correlation",
            Category: "IotOtAdvanced",
            Description: "Two private BACnet endpoints emit I-Am-shaped UDP datagrams after a public source sent Who-Is-shaped datagrams to each within 60 seconds; authorization and device identities are unknown.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R550.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R550",
            maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port" },
            evidenceFields: new[] { "bacnet.request", "bacnet.reply", "matched_conditions", "count", "window_seconds" },
            positiveConditions: new[]
            {
                "Existing PacketHandler and bounded OT classifier must label IPv4 UDP/47808 Who-Is and reverse-direction I-Am-shaped datagrams.",
                "A public IPv4 source must address two distinct RFC1918 targets, each followed by a reverse I-Am-shaped datagram within 60 seconds.",
                "Both distinct request/reply pairs must complete within five minutes, with unique packet IDs and monotonic timestamps."
            },
            negativeConditions: new[]
            {
                "Reject one-way discovery, unrelated reverse peers, generic BACnet, short I-Am envelopes, internal commissioning and malformed or contradictory metadata.",
                "Reject duplicate packet IDs, repeated replies from one target, stale or out-of-order observations, and unsupported link or encrypted traffic.",
                "Do not infer device identity, BACnet authorization, successful exploitation, actual I-Am payload semantics or a confirmed server response."
            },
            minimumConfidence: 86,
            threshold: 2,
            window: ObservationWindow,
            cooldown: Cooldown,
            distinctBy: "public_source+two_distinct_private_reverse_pairs",
            falsePositives: new[]
            {
                "Approved BACnet BBMD, foreign-device registration, routing, commissioning and building-management inventory can legitimately cross a boundary.",
                "NAT, packet loss, spoofed UDP addresses and one-sided capture can make a temporal reverse pair appear causal when it is not."
            },
            tuningKnobs: new[] { "Mode", "ApprovedBacnetGateways", "ApprovedBmsHosts", "ApprovedMaintenanceWindows" },
            requiredTests: new[]
            {
                "real PacketHandler Who-Is and I-Am-shaped UDP producer path and two-target correlation",
                "legitimate private commissioning, one-way discovery and unrelated-peer negatives",
                "truncated, spoofed, contradictory and short I-Am evidence fail closed",
                "duplicate, stale, out-of-order, source isolation, concurrency and cooldown",
                "privacy, candidate Shadow mode, registry uniqueness and confidence floor"
            });

        private sealed class TargetObservation
        {
            internal Guid RequestId;
            internal DateTime RequestAt;
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

        public R550_BacnetCrossBoundaryDiscoveryReplyRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch241245Evidence.Bacnet(record, out var operation)
                || record.IpVersion != 4
                || record.SourcePort != 47808 || record.DestinationPort != 47808
                || record.L4Len is null or > 1476
                || (operation == "whois" && record.L4Len < 8)
                || (operation == "iam" && record.L4Len < 21)
                || record.Sni != null || record.TlsVersion != null || record.Alpn != null
                || record.HttpHost != null || record.HttpUri != null
                || record.HttpRequestHeaders != null || record.HttpMethod != null
                || record.DnsQname != null || record.DnsQtype != null || record.DnsAnswers != null)
                return NoMatch();

            var isRequest = operation == "whois";
            string publicIp;
            string privateIp;
            if (isRequest)
            {
                if (!TryPublicIpv4(record.Source, out publicIp)
                    || !TryPrivateIpv4(record.Destination, out privateIp))
                    return NoMatch();
            }
            else
            {
                if (!TryPrivateIpv4(record.Source, out privateIp)
                    || !TryPublicIpv4(record.Destination, out publicIp))
                    return NoMatch();
            }

            if (!TryObserve(publicIp, privateIp, isRequest, record.Id,
                context.TimestampUtc, out var count, out var suppressed))
                return NoMatch();
            if (suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            // No BACnet device identifier, raw Info, packet payload, or endpoint
            // supplied service metadata is copied into the event.
            var evidence = new[]
            {
                new DetectionEvidenceItem("bacnet.request", "whois-shaped", "bounded-packet-classifier"),
                new DetectionEvidenceItem("bacnet.reply", "iam-shaped", "bounded-packet-classifier"),
                new DetectionEvidenceItem("matched_conditions", "public_to_private_request,reverse_iam_shape,two_distinct_private_targets", "rule"),
                new DetectionEvidenceItem("count", count.ToString(CultureInfo.InvariantCulture), "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "Two private BACnet endpoints sent I-Am-shaped datagrams after public Who-Is probes (authorization unknown)",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.42, "bounded-bacnet-request-reply-shapes");
                    confidence.AddEvidence(0.28, "public-private-reverse-flow");
                    confidence.AddCorrelation(0.22, "two-distinct-private-reply-targets");
                }, count: count, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        private bool TryObserve(string publicIp, string privateIp, bool isRequest,
            Guid id, DateTime now, out int count, out bool suppressed)
        {
            count = 0;
            suppressed = false;
            if (id == Guid.Empty)
                return false;

            lock (_gate)
            {
                if (!_sources.TryGetValue(publicIp, out var bucket))
                {
                    if (_sources.Count >= MaxSources)
                    {
                        var staleSources = new List<string>();
                        foreach (var entry in _sources)
                            if (now > entry.Value.Latest && now - entry.Value.Latest > Cooldown)
                                staleSources.Add(entry.Key);
                        foreach (var key in staleSources)
                            _sources.Remove(key);
                        if (_sources.Count >= MaxSources)
                            return false;
                    }
                    bucket = new SourceBucket { Latest = now };
                    _sources.Add(publicIp, bucket);
                }

                if (now < bucket.Latest || bucket.SeenIds.ContainsKey(id))
                    return false;

                var expiredIds = new List<Guid>();
                foreach (var entry in bucket.SeenIds)
                    if (now >= entry.Value && now - entry.Value > ObservationWindow)
                        expiredIds.Add(entry.Key);
                foreach (var expired in expiredIds)
                    bucket.SeenIds.Remove(expired);

                var expiredTargets = new List<string>();
                foreach (var entry in bucket.Targets)
                {
                    var last = entry.Value.Completed ? entry.Value.CompletedAt : entry.Value.RequestAt;
                    if (now >= last && now - last > ObservationWindow)
                        expiredTargets.Add(entry.Key);
                }
                foreach (var expired in expiredTargets)
                    bucket.Targets.Remove(expired);

                if (bucket.SeenIds.Count >= MaxIdsPerSource
                    || !bucket.Targets.ContainsKey(privateIp)
                       && bucket.Targets.Count >= MaxTargetsPerSource)
                    return false;

                bucket.SeenIds.Add(id, now);
                bucket.Latest = now;
                if (isRequest)
                {
                    if (!bucket.Targets.TryGetValue(privateIp, out var target))
                    {
                        bucket.Targets.Add(privateIp, new TargetObservation
                        {
                            RequestId = id, RequestAt = now
                        });
                    }
                    else if (!target.Completed)
                    {
                        target.RequestId = id;
                        target.RequestAt = now;
                    }
                    return false;
                }

                if (!bucket.Targets.TryGetValue(privateIp, out var pending)
                    || pending.Completed || pending.RequestId == id
                    || now <= pending.RequestAt || now - pending.RequestAt > ReplyWindow)
                    return false;

                pending.Completed = true;
                pending.CompletedAt = now;
                foreach (var target in bucket.Targets.Values)
                    if (target.Completed && now >= target.CompletedAt
                        && now - target.CompletedAt <= ObservationWindow)
                        count++;

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
            var bytes = ip.GetAddressBytes();
            if (!(bytes[0] == 10
                || bytes[0] == 172 && bytes[1] is >= 16 and <= 31
                || bytes[0] == 192 && bytes[1] == 168))
                return false;
            normalized = ip.ToString();
            return true;
        }

        private static bool TryPublicIpv4(string? address, out string normalized)
        {
            normalized = string.Empty;
            if (!NetworkBatch226230Evidence.Public(address)
                || !IPAddress.TryParse(address, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork)
                return false;
            var b = ip.GetAddressBytes();
            if (b[0] is 0 or 10 or 127 or >= 224
                || b[0] == 169 && b[1] == 254
                || b[0] == 192 && (b[1] == 0 || b[1] == 88 && b[2] == 99)
                || b[0] == 198 && (b[1] is 18 or 19 || b[1] == 51 && b[2] == 100)
                || b[0] == 203 && b[1] == 0 && b[2] == 113)
                return false;
            normalized = ip.ToString();
            return true;
        }
    }
}
