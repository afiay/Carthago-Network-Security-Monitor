// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R547_ExternalBacnetWhoIsTargetFanoutRule.cs
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Detects public-to-private, wire-classified BACnet Who-Is requests
    /// addressed to three distinct RFC1918 targets by one public source.
    /// Requests alone do not establish authorization, device presence or exploitation.
    /// </summary>
    public sealed class R547_ExternalBacnetWhoIsTargetFanoutRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly TimeSpan ObservationWindow = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R547",
            Name: "External BACnet Who-Is Target Fanout",
            Category: "IotOtAdvanced",
            Description: "A public IPv4 source sends parsed BACnet Who-Is requests to three distinct RFC1918 destinations on UDP/47808 within five minutes; no response or device-control outcome is inferred.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R547.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R547",
            maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port" },
            evidenceFields: new[] { "bacnet.operation", "matched_conditions", "count", "window_seconds" },
            positiveConditions: new[]
            {
                "The existing bounded UDP producer must classify a BACnet/IP Who-Is request.",
                "One public IPv4 source must send requests to three distinct RFC1918 IPv4 targets within five minutes.",
                "Every observation requires a unique packet ID, coherent IPv4/UDP metadata and both ports 47808."
            },
            negativeConditions: new[]
            {
                "Ignore I-Am, generic BACnet, port-only, multicast, internal-only and repeated single-target traffic.",
                "Ignore missing or contradictory transport, IP, DNS, HTTP or TLS metadata and out-of-order packets.",
                "Do not infer authenticated source identity, unauthorized access, vulnerable targets, replies or exploitation."
            },
            minimumConfidence: 80,
            threshold: 3,
            window: ObservationWindow,
            cooldown: Cooldown,
            distinctBy: "public_source+distinct_rfc1918_destination",
            falsePositives: new[]
            {
                "Authorized BACnet BBMD, foreign-device routing, commissioning, maintenance and inventory can cross network boundaries.",
                "VPN, NAT and spoofed UDP source addresses can distort attribution; asset approval and topology are not verified."
            },
            tuningKnobs: new[] { "Mode", "ApprovedBacnetGateways", "ApprovedBmsHosts" },
            requiredTests: new[]
            {
                "parsed Who-Is positive and legitimate I-Am/internal negative",
                "malformed, spoofed and contradictory evidence",
                "distinct-target deduplication, out-of-order and concurrency",
                "window expiry and cooldown suppression",
                "privacy, registry and Shadow-mode invariants"
            });

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        private readonly object _cooldownGate = new();
        private readonly Dictionary<string, DateTime> _lastEmission = new(StringComparer.Ordinal);

        public R547_ExternalBacnetWhoIsTargetFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch241245Evidence.Bacnet(record, out var operation)
                || !string.Equals(operation, "whois", StringComparison.Ordinal)
                || record.IpVersion != 4
                || record.L4Len is null or < 8 or > 1476
                || record.SourcePort != 47808 || record.DestinationPort != 47808
                || record.Sni != null || record.HttpHost != null || record.HttpUri != null
                || record.HttpRequestHeaders != null || record.DnsAnswers != null
                || !IsPublicUnicastIpv4(record.Source)
                || !IsRfc1918Ipv4(record.Destination))
                return NoMatch();

            var key = record.Source!;
            var count = _observations.Observe(key, record.Destination, record.Id,
                context.TimestampUtc, ObservationWindow, distinctTargets: true);
            if (count != 3)
                return NoMatch();

            lock (_cooldownGate)
            {
                if (_lastEmission.TryGetValue(key, out var previous)
                    && context.TimestampUtc >= previous
                    && context.TimestampUtc - previous < Cooldown)
                    return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

                if (_lastEmission.Count >= 4096 && !_lastEmission.ContainsKey(key))
                {
                    var expired = new List<string>();
                    foreach (var entry in _lastEmission)
                        if (context.TimestampUtc - entry.Value >= Cooldown)
                            expired.Add(entry.Key);
                    foreach (var expiredKey in expired)
                        _lastEmission.Remove(expiredKey);
                    if (_lastEmission.Count >= 4096)
                        return NoMatch();
                }
                _lastEmission[key] = context.TimestampUtc;
            }

            // MatchIot may copy raw Info for later rule IDs. Emit only typed,
            // bounded, non-secret aggregate evidence through the normal engine.
            var evidence = new[]
            {
                new DetectionEvidenceItem("bacnet.operation", "whois", "bounded-packet-parser"),
                new DetectionEvidenceItem("matched_conditions", "parsed_whois,public_to_rfc1918,three_distinct_targets", "rule"),
                new DetectionEvidenceItem("count", count.ToString(CultureInfo.InvariantCulture), "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule"),
                new DetectionEvidenceItem("network.destinationPort", "47808", "packet-header")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "External BACnet Who-Is target fanout observed (authorization unverified)",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.40, "parsed-bacnet-whois");
                    confidence.AddEvidence(0.28, "public-to-private-bacnet");
                    confidence.AddCorrelation(0.16, "three-distinct-private-targets");
                }, count: count, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        private static bool IsRfc1918Ipv4(string? address)
        {
            if (!IPAddress.TryParse(address, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork)
                return false;
            var b = ip.GetAddressBytes();
            return b[0] == 10
                || (b[0] == 172 && b[1] is >= 16 and <= 31)
                || (b[0] == 192 && b[1] == 168);
        }

        private static bool IsPublicUnicastIpv4(string? address)
        {
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
            return true;
        }
    }
}
