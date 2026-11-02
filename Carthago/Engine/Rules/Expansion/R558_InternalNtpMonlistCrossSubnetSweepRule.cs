// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R558_InternalNtpMonlistCrossSubnetSweepRule.cs
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Detects one private IPv4 source sending parser-classified NTP mode-7
    /// monlist requests across three distinct remote private /24s.
    /// This is a request fanout signal, not evidence of a vulnerable
    /// server, a response, amplification, or an authenticated source.
    /// </summary>
    public sealed class R558_InternalNtpMonlistCrossSubnetSweepRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly TimeSpan ObservationWindow = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R558",
            Name: "Internal NTP Mode-7 Monlist Cross-Subnet Sweep",
            Category: "IotOtAdvanced",
            Description: "One RFC1918 source probes three distinct other RFC1918 /24 networks with parsed NTP mode-7 monlist requests in five minutes; no server outcome inferred.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R558.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R558",
            maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port" },
            evidenceFields: new[] { "ntp.operation", "matched_conditions", "count", "window_seconds" },
            positiveConditions: new[]
            {
                "The existing bounded UDP PacketHandler/OtProtocolLight producer must classify an NTP mode-7 MON_GETLIST_1 request.",
                "One RFC1918 source must probe three distinct remote RFC1918 destination /24s on UDP/123 within five minutes, excluding its own /24.",
                "Every observation must have a unique packet ID, client source port >= 1024 and coherent IPv4, UDP and payload-length metadata."
            },
            negativeConditions: new[]
            {
                "Ignore ordinary NTP synchronization, generic port-123 traffic, duplicate packets and repeated requests to one server.",
                "Ignore non-RFC1918 sources and targets, own-/24 targets, same-/24 retries, missing transport metadata and conflicting DNS/TLS/HTTP evidence.",
                "Do not infer source authenticity, vulnerable NTP server versions, server responses, reflected traffic or successful exploitation."
            },
            minimumConfidence: 84,
            threshold: 3,
            window: ObservationWindow,
            cooldown: Cooldown,
            distinctBy: "private_source+distinct_remote_private_destination_24",
            falsePositives: new[]
            {
                "Authorized internal vulnerability scans, routed NTP inventories and network monitoring can probe several private subnets.",
                "UDP source addresses and imported application labels are not authenticated; NAT or one-sided capture can misattribute the source."
            },
            tuningKnobs: new[] { "Mode", "ApprovedInternalScanners", "ApprovedNtpServers", "ApprovedMaintenanceWindows" },
            requiredTests: new[]
            {
                "three-remote-private-subnet parsed positive and normal-sync negative",
                "malformed, port-only and contradictory evidence",
                "duplicate, source isolation and out-of-order controls",
                "window expiry and cooldown suppression",
                "privacy, source-/24 exclusion, registration and Shadow-mode invariants"
            });

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        private readonly object _cooldownGate = new();
        private readonly Dictionary<string, DateTime> _lastEmission = new(StringComparer.Ordinal);

        public R558_InternalNtpMonlistCrossSubnetSweepRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch241245Evidence.NtpMonlist(record)
                || record.IpVersion != 4
                || !record.L4Len.HasValue || record.L4Len.Value is < 8 or > 512
                || record.Length < record.L4Len.Value + 28
                || !record.SourcePort.HasValue || record.SourcePort.Value is < 1024 or > 65535
                || record.Sni != null || record.Alpn != null || record.HttpHost != null
                || record.HttpUri != null || record.HttpRequestHeaders != null
                || record.DnsAnswers != null || record.DnsQtype != null || record.DnsRcode != null
                || !TryPrivateSubnet24(record.Source, out var sourceSubnet)
                || !TryPrivateSubnet24(record.Destination, out var destinationSubnet)
                || string.Equals(sourceSubnet, destinationSubnet, StringComparison.Ordinal))
                return NoMatch();

            // The existing producer validates the mode-7 request prefix. The
            // window counts distinct private destination /24s, not packets or hosts.
            var key = IPAddress.Parse(record.Source!).ToString();
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
                new DetectionEvidenceItem("matched_conditions", "parsed_mode7_monlist,private_cross_subnet,three_distinct_remote_private_24s", "rule"),
                new DetectionEvidenceItem("count", count.ToString(CultureInfo.InvariantCulture), "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule"),
                new DetectionEvidenceItem("network.destinationPort", "123", "packet-header")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Internal NTP mode-7 monlist cross-subnet sweep observed (server outcomes unverified)",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.42, "parsed-ntp-mode7-monlist-request");
                    confidence.AddEvidence(0.26, "private-to-private-cross-subnet-ntp");
                    confidence.AddCorrelation(0.16, "three-distinct-remote-private-subnets");
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

    }
}
