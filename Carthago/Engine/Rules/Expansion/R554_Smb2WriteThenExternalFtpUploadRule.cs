// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed.
// File: Engine/Rules/Expansion/R554_Smb2WriteThenExternalFtpUploadRule.cs
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Correlates two distinct internal SMB2 WRITE-request destination subnets
    /// with a subsequent outbound FTP STOR/APPE control request by the same
    /// private IPv4 source. No file access, transfer or exfiltration outcome
    /// is established by the packet sensor.
    /// </summary>
    public sealed class R554_Smb2WriteThenExternalFtpUploadRule : ExfiltrationAdvancedPrecisionDetectionRuleBase
    {
        private static readonly TimeSpan ObservationWindow = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan SequenceWindow = TimeSpan.FromMinutes(2);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);
        private const int MaxSources = 1024;
        private const int MaxSubnetsPerSource = 32;
        private const int MaxPacketIdsPerSource = 128;

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R554",
            Name: "SMB2 Write Requests Followed by External FTP Upload Command",
            Category: "ExfiltrationAdvanced",
            Description: "A private IPv4 source sends SMB2 WRITE request shapes to two other private /24 networks, then a parsed FTP STOR/APPE command to a public IPv4 server within two minutes; no transfer outcome is known.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R554.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateExfiltrationProfile(
            ruleId: "R554",
            maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Payload },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port" },
            evidenceFields: new[] { "smb.operation", "ftp.operation", "matched_conditions", "count", "window_seconds", "sequence_max_seconds" },
            positiveConditions: new[]
            {
                "The existing PacketHandler must classify two visible client-to-server SMB2 WRITE request shapes on TCP/445 from the same RFC1918 IPv4 source to two different remote RFC1918 /24 networks.",
                "That source must then send a bounded first-segment FTP STOR or APPE command on TCP/21 to a globally routable IPv4 destination within 120 seconds of both SMB2 observations.",
                "Require coherent typed transport, payload-length bounds, distinct packet IDs, monotonic timestamps and one five-minute observation window."
            },
            negativeConditions: new[]
            {
                "Reject SMB2 CREATE/responses, FTP RETR/LIST/responses, one subnet, same-subnet activity, FTP-before-SMB ordering and mismatched sources.",
                "Reject port-only or Info-only claims, malformed or encrypted framing, contradictory HTTP/DNS/TLS metadata, duplicates and stale observations.",
                "Never infer authenticated SMB access, read or collection of files, successful SMB writes, FTP data-channel transfer, server response or exfiltration."
            },
            minimumConfidence: 88,
            threshold: 2,
            window: ObservationWindow,
            cooldown: Cooldown,
            distinctBy: "private_source+two_remote_private_24s+later_public_ftp_upload_request",
            falsePositives: new[]
            {
                "Authorized backup, patch deployment, replication and software distribution can write to several shares before sending an FTP control command.",
                "NAT, VPNs, one-sided capture, TCP segmentation and encrypted SMB/FTPS can conceal or misattribute observations; explicit approved-host policies are needed before alert promotion."
            },
            tuningKnobs: new[] { "Mode", "ApprovedBackupHosts", "ApprovedFtpServers", "ApprovedMaintenanceWindows" },
            requiredTests: new[]
            {
                "actual PacketHandler SMB2 WRITE and FTP STOR/APPE producer-positive; CREATE/RETR negative",
                "two-subnet ordered chain positive and realistic benign or mismatched-source negatives",
                "malformed, Info-only, port-only, encrypted and contradictory evidence fail-closed",
                "duplicate, ordering, two-minute expiry, bounded state, concurrency and cooldown",
                "redacted evidence, candidate Shadow policy and unique registry registration"
            });

        private sealed class SourceBucket
        {
            internal readonly Dictionary<string, DateTime> SmbSubnets = new(StringComparer.Ordinal);
            internal readonly Dictionary<Guid, DateTime> SeenPacketIds = new();
            internal DateTime Latest;
            internal DateTime? LastEmission;
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, SourceBucket> _sources = new(StringComparer.Ordinal);

        public R554_Smb2WriteThenExternalFtpUploadRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!TryQualify(context.Record, out var source, out var subnet, out var isSmb))
                return NoMatch();

            if (!TryObserve(source, subnet, isSmb, context.Record.Id, context.TimestampUtc,
                out var count, out var suppressed))
                return NoMatch();

            if (suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            // No FTP path, SMB share/file name, raw Info, command bytes, user
            // identity or credential is retained in structured event evidence.
            // RuleEngine remains responsible for journal-first delivery.
            var evidence = new[]
            {
                new DetectionEvidenceItem("smb.operation", "smb2.write.request", "bounded-packet-classifier"),
                new DetectionEvidenceItem("ftp.operation", "stor_or_appe.request", "bounded-packet-classifier"),
                new DetectionEvidenceItem("matched_conditions", "two_distinct_private_smb2_write_subnets,subsequent_public_ftp_upload_command", "rule"),
                new DetectionEvidenceItem("count", count.ToString(CultureInfo.InvariantCulture), "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule"),
                new DetectionEvidenceItem("sequence_max_seconds", "120", "rule"),
                new DetectionEvidenceItem("ftp.transfer_status", "request_only_unverified", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "Internal SMB2 WRITE request fanout followed by external FTP upload command (outcomes unverified)",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.46, "bounded-smb2-write-request-shapes");
                    confidence.AddEvidence(0.26, "parsed-public-ftp-upload-command");
                    confidence.AddCorrelation(0.20, "ordered-two-private-subnets-to-public-ftp");
                }, count: count, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        private static bool TryQualify(TrafficRecord record, out string source,
            out string destinationSubnet, out bool isSmb)
        {
            source = string.Empty;
            destinationSubnet = string.Empty;
            isSmb = false;
            if (record.Id == Guid.Empty || !record.IsTcp || record.IsUdp || record.IsQuic
                || record.IpVersion != 4
                || !string.Equals(record.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                || record.SourcePort is null or < 1024 or > 65535
                || record.L4Len is null or < 8 or > 4096
                || record.Length < record.L4Len.Value + 40
                || record.TlsVersion != null || record.Sni != null || record.Alpn != null
                || record.HttpHost != null || record.HttpUri != null || record.HttpMethod != null
                || record.HttpRequestHeaders != null || record.DnsQname != null
                || record.DnsQtype != null || record.DnsRcode != null || record.DnsAnswers != null
                || !TryPrivate24(record.Source, out var sourceSubnet))
                return false;

            source = IPAddress.Parse(record.Source!).ToString();
            if (record.DestinationPort == 445
                && record.L4Len is >= 117 and <= 4096
                && string.Equals(record.ApplicationProtocol, "smb2.write.request", StringComparison.Ordinal)
                && TryPrivate24(record.Destination, out var remoteSubnet)
                && !string.Equals(sourceSubnet, remoteSubnet, StringComparison.Ordinal))
            {
                destinationSubnet = remoteSubnet;
                isSmb = true;
                return true;
            }

            if (record.DestinationPort == 21 && record.L4Len is >= 8 and <= 256
                && NetworkBatch246250Evidence.FtpUpload(record)
                && IsPublicUnicastIpv4(record.Destination))
            {
                destinationSubnet = IPAddress.Parse(record.Destination!).ToString();
                return true;
            }
            return false;
        }

        private bool TryObserve(string source, string subnet, bool isSmb, Guid id,
            DateTime now, out int count, out bool suppressed)
        {
            count = 0;
            suppressed = false;
            lock (_gate)
            {
                if (!_sources.TryGetValue(source, out var bucket))
                {
                    if (_sources.Count >= MaxSources)
                    {
                        var expired = new List<string>();
                        foreach (var entry in _sources)
                            if (now >= entry.Value.Latest
                                && now - entry.Value.Latest >= Cooldown)
                                expired.Add(entry.Key);
                        foreach (var key in expired)
                            _sources.Remove(key);
                        if (_sources.Count >= MaxSources)
                            return false;
                    }
                    bucket = new SourceBucket();
                    _sources.Add(source, bucket);
                }

                if (now < bucket.Latest || bucket.SeenPacketIds.ContainsKey(id))
                    return false;

                var oldIds = new List<Guid>();
                foreach (var entry in bucket.SeenPacketIds)
                    if (now - entry.Value > ObservationWindow)
                        oldIds.Add(entry.Key);
                foreach (var old in oldIds)
                    bucket.SeenPacketIds.Remove(old);

                var oldSubnets = new List<string>();
                foreach (var entry in bucket.SmbSubnets)
                    if (now - entry.Value > SequenceWindow)
                        oldSubnets.Add(entry.Key);
                foreach (var old in oldSubnets)
                    bucket.SmbSubnets.Remove(old);

                if (bucket.SeenPacketIds.Count >= MaxPacketIdsPerSource
                    || isSmb && bucket.SmbSubnets.Count >= MaxSubnetsPerSource
                        && !bucket.SmbSubnets.ContainsKey(subnet))
                    return false;

                bucket.SeenPacketIds.Add(id, now);
                bucket.Latest = now;
                if (isSmb)
                {
                    bucket.SmbSubnets[subnet] = now;
                    return false;
                }

                if (bucket.SmbSubnets.Count < 2)
                    return false;
                // The FTP request must follow both SMB observations strictly;
                // equal timestamps cannot establish a temporal sequence.
                foreach (var observedAt in bucket.SmbSubnets.Values)
                    if (observedAt >= now)
                        return false;

                count = bucket.SmbSubnets.Count;
                // Consume the candidate chain: a subsequent FTP command alone
                // must not re-trigger without fresh SMB observations.
                bucket.SmbSubnets.Clear();
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

        private static bool TryPrivate24(string? address, out string subnet)
        {
            subnet = string.Empty;
            if (!IPAddress.TryParse(address, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork)
                return false;
            var b = ip.GetAddressBytes();
            if (!(b[0] == 10
                || b[0] == 172 && b[1] is >= 16 and <= 31
                || b[0] == 192 && b[1] == 168))
                return false;
            subnet = string.Concat(b[0].ToString(CultureInfo.InvariantCulture), ".",
                b[1].ToString(CultureInfo.InvariantCulture), ".",
                b[2].ToString(CultureInfo.InvariantCulture));
            return true;
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
