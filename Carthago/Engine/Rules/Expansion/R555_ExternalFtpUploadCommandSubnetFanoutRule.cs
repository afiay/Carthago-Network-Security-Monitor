// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Correlates parser-classified outbound FTP STOR/APPE control requests
    /// to three distinct public IPv4 /24s. No data-channel transfer or
    /// successful server storage is inferred from a control command.
    /// </summary>
    public sealed class R555_ExternalFtpUploadCommandSubnetFanoutRule : ExfiltrationAdvancedPrecisionDetectionRuleBase
    {
        private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);
        private const int MaxSources = 1024;
        private const int MaxTargets = 32;
        private const int MaxIds = 128;

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R555",
            Name: "External FTP Upload Command Subnet Fanout",
            Category: "ExfiltrationAdvanced",
            Description: "A private IPv4 client sends parser-classified FTP STOR/APPE requests to three different public /24s in five minutes; server acceptance and data transfer are unknown.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R555.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateExfiltrationProfile(
            ruleId: "R555",
            maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Payload },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port" },
            evidenceFields: new[] { "ftp.operation", "matched_conditions", "count", "window_seconds", "ftp.transfer_status" },
            positiveConditions: new[]
            {
                "Existing PacketHandler/NetworkBatch246250Wire must classify a first-segment FTP STOR or APPE request on client-to-server TCP/21.",
                "One RFC1918 IPv4 source must address three distinct globally routable destination /24 networks within five minutes.",
                "Require coherent typed TCP/IPv4 fields, bounded payload length, unique packet IDs and monotonic timestamps."
            },
            negativeConditions: new[]
            {
                "Reject FTP RETR/LIST, FTP responses, one- or two-subnet transfers, private/reserved destinations, Info-only and port-only claims.",
                "Reject contradictory DNS/HTTP/TLS/QUIC metadata, duplicate packet IDs, out-of-order and expired observations.",
                "Do not infer completed uploads, server acceptance, sensitive content, authenticated client identity or exploitation."
            },
            minimumConfidence: 88,
            threshold: 3,
            window: Window,
            cooldown: Cooldown,
            distinctBy: "private_source+distinct_public_destination_24",
            falsePositives: new[]
            {
                "Authorized multi-site backups, mirroring, deployment automation and managed legacy FTP integrations can contact multiple public networks.",
                "Packet-only observation lacks trusted allowlist/asset roles, FTP server replies, data-channel bytes and encrypted FTPS visibility."
            },
            tuningKnobs: new[] { "Mode", "ApprovedFtpServers", "ApprovedMaintenanceWindows" },
            requiredTests: new[]
            {
                "real PacketHandler STOR/APPE producer-positive and RETR negative",
                "three distinct public /24 positive and legitimate one/two-subnet negatives",
                "reserved, Info-only, malformed, spoofed and contradictory evidence negatives",
                "deduplication, monotonic window, cooldown and concurrency",
                "redaction, Candidate Shadow mode, minimum confidence and unique registry registration"
            });

        private sealed class SourceBucket
        {
            internal readonly Dictionary<string, DateTime> Targets = new(StringComparer.Ordinal);
            internal readonly Dictionary<Guid, DateTime> PacketIds = new();
            internal DateTime Latest;
            internal DateTime? LastEmission;
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, SourceBucket> _sources = new(StringComparer.Ordinal);

        public R555_ExternalFtpUploadCommandSubnetFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!TryQualify(context.Record, out var source, out var target24))
                return NoMatch();

            if (!TryObserve(source, target24, context.Record.Id, context.TimestampUtc,
                out var suppressed))
                return NoMatch();

            if (suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            // Do not include FTP path, raw command bytes, Info, process data or credentials.
            // Normal RuleEngine owns mandatory journal-first persistence and policy.
            var evidence = new[]
            {
                new DetectionEvidenceItem("ftp.operation", "stor_or_appe.request", "bounded-packet-classifier"),
                new DetectionEvidenceItem("matched_conditions", "parsed_ftp_upload_command,three_distinct_public_destination_24s", "rule"),
                new DetectionEvidenceItem("count", "3", "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule"),
                new DetectionEvidenceItem("ftp.transfer_status", "request_only_unverified", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "Outbound FTP upload commands observed toward three public networks (transfer unverified)",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "bounded-ftp-upload-command-shape");
                    confidence.AddEvidence(0.24, "private-to-public-client-direction");
                    confidence.AddCorrelation(0.22, "three-distinct-public-24-networks");
                }, count: 3, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        private static bool TryQualify(TrafficRecord record, out string source, out string target24)
        {
            source = string.Empty;
            target24 = string.Empty;
            if (record.Id == Guid.Empty
                || !record.IsTcp || record.IsUdp || record.IsQuic
                || record.IpVersion != 4
                || !string.Equals(record.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                || record.SourcePort is null or < 1024 or > 65535
                || record.DestinationPort != 21
                || record.L4Len is null or < 8 or > 256
                || record.Length < record.L4Len.Value + 40
                || record.TlsVersion != null || record.Sni != null || record.Alpn != null
                || record.HttpHost != null || record.HttpUri != null || record.HttpMethod != null
                || record.HttpRequestHeaders != null || record.DnsQname != null
                || record.DnsQtype != null || record.DnsRcode != null || record.DnsAnswers != null
                || !NetworkBatch246250Evidence.FtpUpload(record)
                || !TryPrivateSource(record.Source, out source)
                || !TryPublic24(record.Destination, out target24))
                return false;
            return true;
        }

        private bool TryObserve(string source, string target24, Guid id, DateTime now,
            out bool suppressed)
        {
            suppressed = false;
            lock (_gate)
            {
                if (!_sources.TryGetValue(source, out var bucket))
                {
                    if (_sources.Count >= MaxSources)
                    {
                        var stale = new List<string>();
                        foreach (var entry in _sources)
                            if (now >= entry.Value.Latest
                                && now - entry.Value.Latest >= Cooldown)
                                stale.Add(entry.Key);
                        foreach (var key in stale) _sources.Remove(key);
                        if (_sources.Count >= MaxSources) return false;
                    }
                    bucket = new SourceBucket();
                    _sources.Add(source, bucket);
                }

                if (now < bucket.Latest || bucket.PacketIds.ContainsKey(id))
                    return false;

                var staleIds = new List<Guid>();
                foreach (var entry in bucket.PacketIds)
                    if (now - entry.Value > Window) staleIds.Add(entry.Key);
                foreach (var old in staleIds) bucket.PacketIds.Remove(old);

                var staleTargets = new List<string>();
                foreach (var entry in bucket.Targets)
                    if (now - entry.Value > Window) staleTargets.Add(entry.Key);
                foreach (var old in staleTargets) bucket.Targets.Remove(old);

                if (bucket.PacketIds.Count >= MaxIds
                    || bucket.Targets.Count >= MaxTargets
                        && !bucket.Targets.ContainsKey(target24))
                    return false;

                bucket.PacketIds.Add(id, now);
                bucket.Targets[target24] = now;
                bucket.Latest = now;
                if (bucket.Targets.Count < 3) return false;

                // Consume the completed fanout; a later fourth request alone
                // cannot trigger another event without three fresh destinations.
                bucket.Targets.Clear();
                if (bucket.LastEmission.HasValue
                    && now >= bucket.LastEmission.Value
                    && now - bucket.LastEmission.Value < Cooldown)
                {
                    suppressed = true;
                    return true;
                }
                bucket.LastEmission = now;
                return true;
            }
        }

        private static bool TryPrivateSource(string? address, out string normalized)
        {
            normalized = string.Empty;
            if (!IPAddress.TryParse(address, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork) return false;
            var b = ip.GetAddressBytes();
            if (!(b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31
                || b[0] == 192 && b[1] == 168)) return false;
            normalized = ip.ToString();
            return true;
        }

        private static bool TryPublic24(string? address, out string subnet)
        {
            subnet = string.Empty;
            if (!NetworkBatch226230Evidence.Public(address)
                || !IPAddress.TryParse(address, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork) return false;
            var b = ip.GetAddressBytes();
            // Explicitly exclude reserved/documentation/benchmark ranges that
            // generic "not RFC1918" predicates can mistakenly call public.
            if (b[0] is 0 or 10 or 127 or >= 224
                || b[0] == 169 && b[1] == 254
                || b[0] == 192 && (b[1] == 0 || b[1] == 88 && b[2] == 99
                    || b[1] == 168)
                || b[0] == 198 && (b[1] is 18 or 19
                    || b[1] == 51 && b[2] == 100)
                || b[0] == 203 && b[1] == 0 && b[2] == 113)
                return false;
            subnet = string.Concat(b[0].ToString(CultureInfo.InvariantCulture), ".",
                b[1].ToString(CultureInfo.InvariantCulture), ".",
                b[2].ToString(CultureInfo.InvariantCulture));
            return true;
        }
    }
}
