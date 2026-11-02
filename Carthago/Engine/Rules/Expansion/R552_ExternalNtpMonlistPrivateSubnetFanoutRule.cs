// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R552_ExternalNtpMonlistPrivateSubnetFanoutRule.cs
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Detects a single public IPv4 source sending parser-classified NTP
    /// mode-7 monlist requests into three distinct private IPv4 /24s.
    /// This is a request fanout signal, not evidence of a vulnerable
    /// server, a response, amplification, or an authenticated source.
    /// </summary>
    public sealed class R552_ExternalNtpMonlistPrivateSubnetFanoutRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly TimeSpan ObservationWindow = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R552",
            Name: "External NTP Mode-7 Monlist Private-Subnet Fanout",
            Category: "IotOtAdvanced",
            Description: "One public IPv4 source sends parser-classified NTP mode-7 monlist requests to three distinct RFC1918 destination /24s within five minutes; no server response or amplification is inferred.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R552.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R552",
            maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port" },
            evidenceFields: new[] { "ntp.operation", "matched_conditions", "count", "window_seconds" },
            positiveConditions: new[]
            {
                "The existing bounded UDP PacketHandler/OtProtocolLight producer must classify an NTP mode-7 MON_GETLIST_1 request.",
                "One globally routable unicast IPv4 source must address three distinct RFC1918 destination /24 networks on UDP/123 within five minutes.",
                "Every observation must have a unique packet ID, client source port >= 1024 and coherent IPv4, UDP and payload-length metadata."
            },
            negativeConditions: new[]
            {
                "Ignore ordinary NTP synchronization, generic port-123 traffic, duplicate packets and repeated requests to one server.",
                "Ignore nonpublic or reserved sources, non-RFC1918 destinations, same-subnet retries, missing transport metadata and conflicting DNS/TLS/HTTP evidence.",
                "Do not infer source authenticity, vulnerable NTP server versions, server responses, reflected traffic or successful exploitation."
            },
            minimumConfidence: 84,
            threshold: 3,
            window: ObservationWindow,
            cooldown: Cooldown,
            distinctBy: "public_source+distinct_rfc1918_destination_24",
            falsePositives: new[]
            {
                "Authorized external vulnerability scans, managed service provider probes and legacy NTP inventory can target several private networks behind a gateway.",
                "UDP source addresses can be spoofed; a public-to-private packet view may be post-NAT and does not authenticate the originating host."
            },
            tuningKnobs: new[] { "Mode", "ApprovedExternalScanners", "ApprovedNtpServers", "ApprovedMaintenanceWindows" },
            requiredTests: new[]
            {
                "three-private-subnet parsed positive and normal-sync negative",
                "malformed, port-only and contradictory evidence",
                "duplicate, source isolation and out-of-order controls",
                "window expiry and cooldown suppression",
                "privacy, registration and Shadow-mode invariants"
            });

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        private readonly object _cooldownGate = new();
        private readonly Dictionary<string, DateTime> _lastEmission = new(StringComparer.Ordinal);

        public R552_ExternalNtpMonlistPrivateSubnetFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch241245Evidence.NtpMonlist(record)
                || record.IpVersion != 4
                || !record.L4Len.HasValue || record.L4Len.Value is < 8 or > 512
                || !record.SourcePort.HasValue || record.SourcePort.Value is < 1024 or > 65535
                || record.Sni != null || record.HttpHost != null || record.HttpUri != null
                || record.HttpRequestHeaders != null || record.DnsAnswers != null
                || record.DnsQtype != null || record.DnsRcode != null
                || !IsPublicUnicastIpv4(record.Source)
                || !TryPrivateSubnet24(record.Destination, out var destinationSubnet))
                return NoMatch();

            // The existing producer validates the mode-7 request prefix. The
            // window counts distinct private destination /24s, not packets or hosts.
            var key = record.Source!;
            var count = _observations.Observe(key, destinationSubnet, record.Id,
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
                new DetectionEvidenceItem("matched_conditions", "parsed_mode7_monlist,public_to_rfc1918,three_distinct_private_subnets", "rule"),
                new DetectionEvidenceItem("count", count.ToString(CultureInfo.InvariantCulture), "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule"),
                new DetectionEvidenceItem("network.destinationPort", "123", "packet-header")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "External NTP mode-7 monlist probing across private subnets (server outcomes unverified)",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.42, "parsed-ntp-mode7-monlist-request");
                    confidence.AddEvidence(0.26, "public-to-private-ntp");
                    confidence.AddCorrelation(0.16, "three-distinct-private-subnets");
                }, count: count, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        private static bool TryPrivateSubnet24(string? address, out string subnet)
        {
            subnet = string.Empty;
            if (!IPAddress.TryParse(address, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork)
                return false;
            var b = ip.GetAddressBytes();
            if (!(b[0] == 10
                || (b[0] == 172 && b[1] is >= 16 and <= 31)
                || (b[0] == 192 && b[1] == 168)))
                return false;
            subnet = $"{b[0]}.{b[1]}.{b[2]}.0/24";
            return true;
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
