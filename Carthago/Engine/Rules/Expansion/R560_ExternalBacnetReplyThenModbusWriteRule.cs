// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R560_ExternalBacnetReplyThenModbusWriteRule.cs
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Correlates a single-target public BACnet Who-Is, reverse I-Am-shaped
    /// datagram and later public-origin Modbus write-request shape. This does
    /// not authenticate identities or establish controller outcomes.
    /// </summary>
    public sealed class R560_ExternalBacnetReplyThenModbusWriteRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly TimeSpan ObservationWindow = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan ReplyWindow = TimeSpan.FromSeconds(60);
        private static readonly TimeSpan WriteWindow = TimeSpan.FromSeconds(120);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);
        private const int MaxSources = 512;
        private const int MaxTargetsPerSource = 16;
        private const int MaxIdsPerSource = 96;

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R560",
            Name: "External BACnet Reply Followed by Modbus Write Request",
            Category: "IotOtAdvanced",
            Description: "One public peer sends BACnet Who-Is, observes a reverse I-Am-shaped datagram, then sends a Modbus write request to the same private target; outcomes unknown.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R560.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R560",
            maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port" },
            evidenceFields: new[] { "ot.discovery", "ot.reply_shape", "ot.write_request", "matched_conditions", "count", "window_seconds" },
            positiveConditions: new[]
            {
                "PacketHandler classifies IPv4 UDP/47808 Who-Is and reverse I-Am-shaped datagrams plus a later TCP/502 Modbus write-request shape.",
                "All three observations involve the same public IPv4 peer and exact RFC1918 target: reverse reply within 60 seconds, write within 120 seconds of reply, total within 300 seconds.",
                "All three packet IDs are unique and timestamps are monotonic."
            },
            negativeConditions: new[]
            {
                "Reject absent/unrelated replies, wrong order, Modbus reads/responses, malformed/contradictory transport, reserved sources and Info/port-only guesses.",
                "Reject duplicate IDs, stale packets, saturation and unsupported capture; no authenticated device identity, accepted write or exploit inference."
            },
            minimumConfidence: 90,
            threshold: 1,
            window: ObservationWindow,
            cooldown: Cooldown,
            distinctBy: "public_peer+private_target+three_ordered_directional_shapes",
            falsePositives: new[]
            {
                "Approved BACnet BBMD, foreign-device routing, commissioning, maintenance and multi-protocol gateways can produce the same pattern.",
                "NAT, UDP spoofing, I-Am proxies and one-sided capture can distort temporal attribution."
            },
            tuningKnobs: new[] { "Mode", "ApprovedBacnetGateways", "ApprovedEngineeringHosts", "ApprovedMaintenanceWindows" },
            requiredTests: new[]
            {
                "real PacketHandler three-stage producer positive and benign negative",
                "missing reply, wrong source/target, read and malformed frame negatives",
                "Info-only, contradictory fields, duplicate and out-of-order evidence",
                "60/120/300 second boundaries, cooldown and bounded state",
                "privacy, registry, Shadow and confidence invariants"
            });

        private enum Step { Request, Reply, Write }

        private sealed class TargetObservation
        {
            internal int Stage;
            internal DateTime RequestAt;
            internal DateTime ReplyAt;
            internal DateTime LastAt;
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

        public R560_ExternalBacnetReplyThenModbusWriteRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (r.Id == Guid.Empty || r.IpVersion != 4 || r.IsQuic
                || r.Sni != null || r.TlsVersion != null || r.Alpn != null
                || r.HttpHost != null || r.HttpUri != null || r.HttpMethod != null
                || r.HttpRequestHeaders != null || r.DnsQname != null
                || r.DnsQtype != null || r.DnsAnswers != null || r.DnsRcode != null)
                return NoMatch();

            Step step;
            if (NetworkBatch241245Evidence.Bacnet(r, out var operation)
                && r.SourcePort == 47808 && r.DestinationPort == 47808
                && (operation == "whois" && r.L4Len is >= 8 and <= 1476
                    || operation == "iam" && r.L4Len is >= 21 and <= 1476))
                step = operation == "whois" ? Step.Request : Step.Reply;
            else if (NetworkBatch236240Evidence.ModbusWrite(r)
                && r.SourcePort is >= 1024 and <= 65535 and not 502
                && r.DestinationPort == 502 && r.L4Len is >= 12 and <= 260)
                step = Step.Write;
            else
                return NoMatch();

            string publicIp, privateIp;
            if (step == Step.Reply)
            {
                if (!TryPrivateIpv4(r.Source, out privateIp)
                    || !TryPublicIpv4(r.Destination, out publicIp))
                    return NoMatch();
            }
            else if (!TryPublicIpv4(r.Source, out publicIp)
                || !TryPrivateIpv4(r.Destination, out privateIp))
                return NoMatch();

            if (!TryObserve(publicIp, privateIp, step, r.Id, context.TimestampUtc, out var suppressed))
                return NoMatch();
            if (suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            // Only fixed operation labels and aggregate conditions; never raw Info,
            // packet bytes, register addresses, credentials or device identifiers.
            var evidence = new[]
            {
                new DetectionEvidenceItem("ot.discovery", "bacnet.whois-shaped", "bounded-packet-classifier"),
                new DetectionEvidenceItem("ot.reply_shape", "bacnet.iam-shaped", "bounded-packet-classifier"),
                new DetectionEvidenceItem("ot.write_request", "modbus.write.request", "bounded-packet-classifier"),
                new DetectionEvidenceItem("matched_conditions", "same_public_peer,same_private_target,reverse_iam_shape,ordered_modbus_write", "rule"),
                new DetectionEvidenceItem("count", "1", "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "External BACnet discovery and reverse I-Am-shaped traffic preceded a Modbus write request at one private target (outcome unknown)",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.44, "three-bounded-packet-shapes");
                    confidence.AddEvidence(0.30, "reverse-direction-same-peer-target");
                    confidence.AddCorrelation(0.22, "ordered-discovery-reply-write");
                }, count: 1, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        private bool TryObserve(string publicIp, string privateIp, Step step,
            Guid id, DateTime now, out bool suppressed)
        {
            suppressed = false;
            lock (_gate)
            {
                if (!_sources.TryGetValue(publicIp, out var bucket))
                {
                    if (step != Step.Request)
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
                    _sources.Add(publicIp, bucket);
                }

                if (now < bucket.Latest || bucket.SeenIds.ContainsKey(id))
                    return false;

                var oldIds = new List<Guid>();
                foreach (var entry in bucket.SeenIds)
                    if (now >= entry.Value && now - entry.Value > ObservationWindow)
                        oldIds.Add(entry.Key);
                foreach (var old in oldIds)
                    bucket.SeenIds.Remove(old);

                var oldTargets = new List<string>();
                foreach (var entry in bucket.Targets)
                    if (now >= entry.Value.LastAt && now - entry.Value.LastAt > ObservationWindow)
                        oldTargets.Add(entry.Key);
                foreach (var old in oldTargets)
                    bucket.Targets.Remove(old);

                if (bucket.SeenIds.Count >= MaxIdsPerSource)
                    return false;

                if (step == Step.Request)
                {
                    if (!bucket.Targets.TryGetValue(privateIp, out var target))
                    {
                        if (bucket.Targets.Count >= MaxTargetsPerSource)
                            return false;
                        target = new TargetObservation();
                        bucket.Targets.Add(privateIp, target);
                    }
                    target.Stage = 1;
                    target.RequestAt = now;
                    target.ReplyAt = default;
                    target.LastAt = now;
                    bucket.SeenIds.Add(id, now);
                    bucket.Latest = now;
                    return false;
                }

                if (!bucket.Targets.TryGetValue(privateIp, out var pending))
                    return false;
                if (step == Step.Reply)
                {
                    if (pending.Stage != 1 || now <= pending.RequestAt
                        || now - pending.RequestAt > ReplyWindow)
                        return false;
                    pending.Stage = 2;
                    pending.ReplyAt = now;
                    pending.LastAt = now;
                    bucket.SeenIds.Add(id, now);
                    bucket.Latest = now;
                    return false;
                }
                if (pending.Stage != 2 || now <= pending.ReplyAt
                    || now - pending.ReplyAt > WriteWindow
                    || now - pending.RequestAt > ObservationWindow)
                    return false;
                pending.Stage = 3;
                pending.LastAt = now;
                bucket.SeenIds.Add(id, now);
                bucket.Latest = now;
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
                || b[0] == 100 && b[1] is >= 64 and <= 127
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
