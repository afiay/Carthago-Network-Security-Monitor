// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R546_NtpMonlistOutboundTargetFanoutRule.cs
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Detects a single RFC1918 host sending wire-classified NTP mode-7
    /// monlist requests to several distinct public NTP endpoints.
    /// This is a request fanout signal, not evidence of a vulnerable
    /// server, a response, amplification, or an authenticated source.
    /// </summary>
    public sealed class R546_NtpMonlistOutboundTargetFanoutRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly TimeSpan ObservationWindow = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R546",
            Name: "Outbound NTP Mode-7 Monlist Target Fanout",
            Category: "IotOtAdvanced",
            Description: "Wire-classified mode-7 monlist requests are addressed to three distinct public IPv4 destinations on UDP/123 from one RFC1918 source within five minutes; no response or exploit outcome is inferred.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R546.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R546",
            maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port" },
            evidenceFields: new[] { "ntp.operation", "matched_conditions", "count", "window_seconds" },
            positiveConditions: new[]
            {
                "A bounded UDP packet producer must classify an NTP mode-7 MON_GETLIST_1 request.",
                "One RFC1918 IPv4 source must contact three distinct globally routable IPv4 destinations on UDP/123 within five minutes.",
                "Every observation must have a unique packet ID and coherent IPv4, UDP and payload-length metadata."
            },
            negativeConditions: new[]
            {
                "Ignore ordinary NTP synchronization, generic port-123 traffic, duplicate packets and repeated requests to one server.",
                "Ignore nonpublic destinations, non-RFC1918 sources, missing transport metadata and conflicting DNS/TLS/HTTP evidence.",
                "Do not infer source authenticity, vulnerable NTP server versions, server responses, reflected traffic or successful exploitation."
            },
            minimumConfidence: 80,
            threshold: 3,
            window: ObservationWindow,
            cooldown: Cooldown,
            distinctBy: "source+distinct_public_destination",
            falsePositives: new[]
            {
                "Approved vulnerability scanners, NTP monitoring and authorized network assessments can probe multiple NTP servers.",
                "UDP source addresses can be spoofed; packet headers do not authenticate the originating host."
            },
            tuningKnobs: new[] { "Mode", "ApprovedNtpScanners", "ApprovedNtpServers" },
            requiredTests: new[]
            {
                "three-target parsed positive and normal-sync negative",
                "malformed, port-only and contradictory evidence",
                "duplicate, source isolation and out-of-order controls",
                "window expiry and cooldown suppression",
                "privacy, registration and Shadow-mode invariants"
            });

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        private readonly object _cooldownGate = new();
        private readonly Dictionary<string, DateTime> _lastEmission = new(StringComparer.Ordinal);

        public R546_NtpMonlistOutboundTargetFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch241245Evidence.NtpMonlist(record)
                || record.IpVersion != 4
                || !record.L4Len.HasValue || record.L4Len.Value is < 8 or > 512
                || !record.SourcePort.HasValue || record.SourcePort.Value is < 1 or > 65535
                || record.Sni != null || record.HttpHost != null || record.HttpUri != null
                || record.HttpRequestHeaders != null || record.DnsAnswers != null
                || !IsRfc1918Ipv4(record.Source)
                || !IsPublicUnicastIpv4(record.Destination))
                return NoMatch();

            // The existing producer validates the mode-7 request prefix. The
            // window counts unique destination addresses, not packet volume.
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

            // MatchIot is intentionally not used: it can persist raw Info for
            // newer IDs. Only aggregate and parser-attributed fields are kept.
            var evidence = new[]
            {
                new DetectionEvidenceItem("ntp.operation", "mode7.monlist", "bounded-packet-parser"),
                new DetectionEvidenceItem("matched_conditions", "parsed_mode7_monlist,rfc1918_to_public,three_distinct_targets", "rule"),
                new DetectionEvidenceItem("count", count.ToString(CultureInfo.InvariantCulture), "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule"),
                new DetectionEvidenceItem("network.destinationPort", "123", "packet-header")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Outbound NTP mode-7 monlist request fanout observed (server outcomes unverified)",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.42, "parsed-ntp-mode7-monlist-request");
                    confidence.AddEvidence(0.26, "rfc1918-to-public-ntp");
                    confidence.AddCorrelation(0.16, "three-distinct-public-targets");
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
            // Public() is a general helper; exclude special-purpose ranges
            // that should not be treated as public targets for this rule.
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
