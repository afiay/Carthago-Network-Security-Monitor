// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R545_ExternalBacnetIAmAnnouncementRule.cs
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Flags repeated, wire-classified BACnet I-Am announcements crossing from a
    /// globally routed IPv4 source to an RFC1918 destination. This is a
    /// discovery/exposure candidate, never proof of device spoofing or control.
    /// </summary>
    public sealed class R545_ExternalBacnetIAmAnnouncementRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly TimeSpan ObservationWindow = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R545",
            Name: "External BACnet I-Am Announcement",
            Category: "IotOtAdvanced",
            Description: "Repeated parsed BACnet/IP I-Am advertisements from a public IPv4 source to an RFC1918 destination; does not assert spoofing or exploitation.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R545.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R545",
            maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port" },
            evidenceFields: new[] { "bacnet.operation", "matched_conditions", "count", "window_seconds" },
            positiveConditions: new[]
            {
                "Two distinct, bounded, wire-classified BACnet I-Am datagrams must be observed within five minutes.",
                "The source must be a globally routed IPv4 address and the destination must be RFC1918.",
                "Both source and destination UDP ports must be 47808; no free-form Info or port-only match."
            },
            negativeConditions: new[]
            {
                "Ignore Who-Is, generic BACnet, invalid transport and internal-only I-Am traffic.",
                "Do not infer device identity, authorization, successful spoofing or physical control.",
                "Do not page without separately verified BACnet routing/BBMD and approved-device context."
            },
            minimumConfidence: 80,
            threshold: 2,
            window: ObservationWindow,
            cooldown: Cooldown,
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Authorized BACnet BBMD/foreign-device routing, VPN/NAT paths and commissioning can produce cross-boundary I-Am."
            },
            tuningKnobs: new[] { "Mode", "ApprovedBacnetGateways", "ApprovedBmsHosts" },
            requiredTests: new[]
            {
                "parsed positive and internal negative", "spoofed or malformed evidence",
                "deduplication and out-of-order", "window and cooldown",
                "privacy and shadow-policy invariants"
            });

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        private readonly object _cooldownGate = new();
        private readonly Dictionary<string, DateTime> _lastEmission = new(StringComparer.Ordinal);

        public R545_ExternalBacnetIAmAnnouncementRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch241245Evidence.Bacnet(record, out var operation)
                || !string.Equals(operation, "iam", StringComparison.Ordinal)
                || record.SourcePort != 47808 || record.DestinationPort != 47808
                || record.Sni != null || record.HttpHost != null || record.HttpUri != null
                || record.DnsAnswers != null
                || !IsPublicUnicastIpv4(record.Source) || !IsRfc1918Ipv4(record.Destination))
                return NoMatch();

            // The packet producer identifies only an I-Am frame, not the
            // asserted BACnet device ID, an authenticated gateway or outcome.
            var key = record.Source + "|" + record.Destination;
            var count = _observations.Observe(key, "bacnet.iam", record.Id,
                context.TimestampUtc, ObservationWindow, distinctTargets: false);
            if (count != 2)
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
                        return NoMatch(); // fail closed on bounded-state exhaustion
                }

                _lastEmission[key] = context.TimestampUtc;
            }

            // Do not use MatchIot here: that legacy helper can include raw
            // record.Info for IDs outside its historical redaction ranges.
            // CreateDetectionEvent emits only endpoint and non-sensitive
            // boolean/aggregate metadata; no BACnet payload or device ID.
            var evidence = new[]
            {
                new DetectionEvidenceItem("bacnet.operation", "iam", "bounded-packet-parser"),
                new DetectionEvidenceItem("matched_conditions", "parsed_iam,udp_47808,public_to_rfc1918,repeated", "rule"),
                new DetectionEvidenceItem("count", count.ToString(CultureInfo.InvariantCulture), "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule"),
                new DetectionEvidenceItem("network.destinationPort", "47808", "packet-header")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "Repeated external BACnet I-Am announcements observed (authorization unverified)",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.40, "parsed-bacnet-iam");
                    confidence.AddEvidence(0.28, "external-to-private-boundary");
                    confidence.AddCorrelation(0.16, "two-distinct-packet-observations");
                }, count: count, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        private static bool IsRfc1918Ipv4(string? address)
        {
            if (!IPAddress.TryParse(address, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork)
                return false;
            var bytes = ip.GetAddressBytes();
            return bytes[0] == 10
                || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
                || (bytes[0] == 192 && bytes[1] == 168);
        }

        private static bool IsPublicUnicastIpv4(string? address)
        {
            if (!NetworkBatch226230Evidence.Public(address)
                || !IPAddress.TryParse(address, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork)
                return false;

            var b = ip.GetAddressBytes();
            // Fail closed on documentation, benchmarking, special-purpose and
            // link-local blocks that a simple "not RFC1918" check mislabels.
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
