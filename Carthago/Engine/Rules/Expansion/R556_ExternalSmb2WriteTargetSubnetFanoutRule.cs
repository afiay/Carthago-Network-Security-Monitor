// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed.
// File: Engine/Rules/Expansion/R556_ExternalSmb2WriteTargetSubnetFanoutRule.cs
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Correlates SMB2 WRITE request shapes from one public IPv4 source across
    /// three distinct private destination /24s. This is not evidence of successful
    /// writes, admin-share use, remote execution or ransomware.
    /// </summary>
    public sealed class R556_ExternalSmb2WriteTargetSubnetFanoutRule : IdentityAccessPrecisionDetectionRuleBase
    {
        private static readonly TimeSpan ObservationWindow = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R556",
            Name: "External SMB2 Write Request Private-Subnet Fanout",
            Category: "IdentityAccess",
            Description: "A public IPv4 client sends bounded SMB2 WRITE request shapes to three distinct RFC1918 destination /24s in five minutes; authentication and write outcomes are unknown.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R556.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIdentityAccessProfile(
            ruleId: "R556",
            maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Payload },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port" },
            evidenceFields: new[] { "smb.operation", "matched_conditions", "count", "window_seconds" },
            positiveConditions: new[]
            {
                "PacketHandler's bounded NetworkBatch246250Wire classifier must recognize a client-to-server SMB2 WRITE request shape on visible TCP/445 plaintext.",
                "One globally routable public IPv4 source must address three distinct RFC1918 destination /24 networks within five minutes.",
                "Require coherent TCP/IPv4 headers, bounded first-segment length, distinct packet IDs and monotonic observations."
            },
            negativeConditions: new[]
            {
                "Reject SMB2 CREATE, responses, encrypted SMB3, generic port-445 connections, Info-only labels, one-subnet retries, nonpublic sources and external destinations.",
                "Reject missing or contradictory transport, HTTP, DNS or TLS fields, duplicate IDs and out-of-order observations.",
                "Never infer authenticated share access, ADMIN$/C$ use, successful file writes, file contents, remote execution or ransomware."
            },
            minimumConfidence: 90,
            threshold: 3,
            window: ObservationWindow,
            cooldown: Cooldown,
            distinctBy: "public_source+distinct_private_destination_24",
            falsePositives: new[]
            {
                "Authorized external backup gateways, cross-boundary remote administration and managed file replication may produce similar requests.",
                "NAT and VPN gateways can obscure source identity; SMB encryption, segmentation and one-sided capture can hide requests."
            },
            tuningKnobs: new[] { "Mode", "ApprovedBackupServers", "ApprovedFileServers", "ApprovedMaintenanceWindows" },
            requiredTests: new[]
            {
                "wire-parser SMB2 WRITE positive and CREATE/response negative",
                "three private destination subnets from one public source, and benign one-subnet/cross-source negatives",
                "malformed, Info-only and contradictory/encrypted evidence fail-closed",
                "duplicate, monotonic, window, cooldown and concurrency controls",
                "privacy, candidate Shadow policy and registry uniqueness"
            });

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        private readonly object _cooldownGate = new();
        private readonly Dictionary<string, DateTime> _lastEmission = new(StringComparer.Ordinal);

        public R556_ExternalSmb2WriteTargetSubnetFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (record.Id == Guid.Empty
                || !record.IsTcp || record.IsUdp || record.IsQuic
                || record.IpVersion != 4
                || !string.Equals(record.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(record.ApplicationProtocol, "smb2.write.request", StringComparison.Ordinal)
                || record.SourcePort is null or < 1024 or > 65535
                || record.DestinationPort != 445
                || record.L4Len is null or < 117 or > 4096
                || record.Length < record.L4Len.Value + 40
                || record.TlsVersion != null || record.Sni != null || record.Alpn != null
                || record.HttpHost != null || record.HttpUri != null || record.HttpMethod != null
                || record.HttpRequestHeaders != null || record.DnsQname != null
                || record.DnsQtype != null || record.DnsRcode != null || record.DnsAnswers != null
                || !TryPublicSource(record.Source, out var source)
                || !TryPrivate24(record.Destination, out var targetSubnet))
                return NoMatch();

            var count = _observations.Observe(source, targetSubnet, record.Id,
                context.TimestampUtc, ObservationWindow, distinctTargets: true);
            if (count != 3)
                return NoMatch();

            lock (_cooldownGate)
            {
                if (_lastEmission.TryGetValue(source, out var previous)
                    && context.TimestampUtc >= previous
                    && context.TimestampUtc - previous < Cooldown)
                    return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

                if (_lastEmission.Count >= 4096 && !_lastEmission.ContainsKey(source))
                {
                    var expired = new List<string>();
                    foreach (var entry in _lastEmission)
                        if (context.TimestampUtc >= entry.Value
                            && context.TimestampUtc - entry.Value >= Cooldown)
                            expired.Add(entry.Key);
                    foreach (var key in expired)
                        _lastEmission.Remove(key);
                    if (_lastEmission.Count >= 4096)
                        return NoMatch();
                }
                _lastEmission[source] = context.TimestampUtc;
            }

            // No raw Info, SMB payload, file/share path, account, or secret enters
            // the event. The normal RuleEngine owns journal-first persistence.
            var evidence = new[]
            {
                new DetectionEvidenceItem("smb.operation", "smb2.write.request", "bounded-packet-classifier"),
                new DetectionEvidenceItem("matched_conditions", "parsed_smb2_write,public_to_private_subnets,three_distinct_24s", "rule"),
                new DetectionEvidenceItem("count", count.ToString(CultureInfo.InvariantCulture), "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule"),
                new DetectionEvidenceItem("network.destinationPort", "445", "packet-header")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "Public-origin SMB2 WRITE requests observed across three private subnets (outcomes unverified)",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.44, "bounded-smb2-write-request-shape");
                    confidence.AddEvidence(0.25, "public-to-private-cross-boundary-traffic");
                    confidence.AddCorrelation(0.20, "three-distinct-private-destination-subnets");
                }, count: count, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        private static bool TryPublicSource(string? value, out string normalized)
        {
            normalized = string.Empty;
            if (!NetworkBatch226230Evidence.Public(value)
                || !IPAddress.TryParse(value, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork)
                return false;
            var b = ip.GetAddressBytes();
            // Exclude shared/reserved/test ranges that generic not-RFC1918
            // classification can mislabel as public.
            if (b[0] == 100 && b[1] is >= 64 and <= 127
                || b[0] == 192 && (b[1] == 0 || b[1] == 88 && b[2] == 99)
                || b[0] == 198 && (b[1] is 18 or 19
                    || b[1] == 51 && b[2] == 100)
                || b[0] == 203 && b[1] == 0 && b[2] == 113)
                return false;
            normalized = ip.ToString();
            return true;
        }

        private static bool TryPrivate24(string? value, out string subnet)
        {
            subnet = string.Empty;
            if (!IPAddress.TryParse(value, out var ip)
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
    }
}
