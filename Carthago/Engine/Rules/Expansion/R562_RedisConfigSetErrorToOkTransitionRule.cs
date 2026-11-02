// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.
// File: Engine/Rules/Expansion/R562_RedisConfigSetErrorToOkTransitionRule.cs
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Correlates two RESP2 error replies to CONFIG SET attempts followed by a
    /// separate connection's correlated +OK-shaped reply. The latter is an
    /// unauthenticated wire observation, not an attested configuration change.
    /// </summary>
    public sealed class R562_RedisConfigSetErrorToOkTransitionRule : DatabaseServiceExposurePrecisionDetectionRuleBase
    {
        private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan FollowUp = TimeSpan.FromMinutes(2);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);
        private const int MaxPairs = 1024;
        private const int MaxPortsPerPair = 32;
        private const int MaxIdsPerPair = 96;

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R562",
            Name: "Redis CONFIG SET Error-to-OK Reply Transition",
            Category: "DatabaseServiceExposure",
            Description: "Two correlated RESP2 CONFIG SET errors on separate connections followed by a distinct +OK-shaped reply from the same private server to the same public client; authorization and server identity unknown.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R562.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R562",
            Name = "Redis CONFIG SET Error-to-OK Reply Transition",
            Category = "DatabaseServiceExposure",
            Description = "Bounded error-to-OK RESP2 reply transition across three TCP connections, not an authenticated Redis configuration change.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination_or_host", "protocol_or_port" },
            EvidenceFields = new[] { "redis.reply_sequence", "redis.distinct_connections", "matched_conditions", "count", "window_seconds" },
            PositiveConditions = new[]
            {
                "PacketHandler must correlate each RESP2 reply to a complete first CONFIG SET command after SYN/SYN-ACK, with bounded first-payload ordering.",
                "Two errors on distinct client ephemeral TCP ports must precede a +OK-shaped reply on a third port for the same public client/private server pair.",
                "All three replies must fall in five minutes, and the +OK-shaped reply must follow the second error within 120 seconds."
            },
            NegativeConditions = new[]
            {
                "Reject errors without a later +OK, +OK before the errors, repeated client ports, unrelated commands, malformed frames and missing handshake evidence.",
                "Reject port/Info-only claims, contradictory protocol fields, TLS, nonpublic clients, duplicate IDs and out-of-order timestamps.",
                "A +OK wire reply is not authenticated Redis identity, confirmed configuration persistence, an authorization violation or exploitation."
            },
            FalsePositives = new[]
            {
                "Approved administration may correct invalid CONFIG SET parameters and retry from fresh connections.",
                "NAT, proxies, spoofed wire replies and partial TCP capture may misattribute the apparent client/server or hide the sequence."
            },
            MinimumConfidence = 88,
            WindowThreshold = 3,
            Window = TimeSpan.FromMinutes(5),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "public_client+private_redis_server+two_error_ports+distinct_ok_port",
            TuningKnobs = new[] { "Mode", "ApprovedAdminHosts", "MaintenanceWindows" },
            RequiredTests = new[]
            {
                "real bidirectional TCP producer positive and reply-shape negatives",
                "two errors before a third-port OK, order and 120-second follow-up",
                "spoofed, incomplete, encrypted and imported evidence fail-closed",
                "distinct ports, duplicate IDs, window expiry, cooldown and concurrent evaluation",
                "privacy, explicit approved-admin suppression, Shadow/Candidate policy and registry uniqueness"
            }
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        private sealed class Bucket
        {
            internal readonly Dictionary<int, DateTime> ErrorPorts = new();
            internal readonly Dictionary<Guid, DateTime> Seen = new();
            internal DateTime LastAt;
            internal DateTime? LastEmission;
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, Bucket> _pairs = new(StringComparer.Ordinal);

        public R562_RedisConfigSetErrorToOkTransitionRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            var isError = r.RedisRespConfigSetReplyErrorObserved;
            var isOk = r.RedisRespConfigSetReplyOkObserved;
            if (r.Id == Guid.Empty || isError == isOk || r.RedisRespConfigSetRequestObserved
                || !r.IsTcp || r.IsUdp || r.IsQuic || r.IpVersion != 4
                || !string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(r.ApplicationProtocol, "redis.resp2", StringComparison.Ordinal)
                || r.SourcePort != 6379 || r.DestinationPort is null or < 1024 or > 65535 or 6379
                || r.L4Len is null or < 5 or > 512 || r.Length < r.L4Len.Value + 40
                || r.Sni != null || r.TlsVersion != null || r.Alpn != null
                || r.HttpHost != null || r.HttpUri != null || r.HttpMethod != null
                || r.HttpRequestHeaders != null || r.DnsQname != null || r.DnsQtype != null
                || r.DnsRcode != null || r.DnsAnswers != null
                || !TryPrivate(r.Source, out var server)
                || !TryPublic(r.Destination, out var client))
                return NoMatch();

            if (IsApprovedClient(client, ApprovedAssetRegistry.Current))
                return NoMatch();

            if (!Observe(client + "|" + server, r.DestinationPort.Value, r.Id,
                    isError, context.TimestampUtc, out var suppressed))
                return NoMatch();
            if (suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("redis.reply_sequence", "two_errors_then_ok_shaped_reply", "packet-handler-correlator"),
                new DetectionEvidenceItem("redis.distinct_connections", "3", "rule"),
                new DetectionEvidenceItem("matched_conditions", "same_public_client,same_private_server,ordered_distinct_ports", "rule"),
                new DetectionEvidenceItem("count", "3", "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Redis CONFIG SET error replies followed by a correlated OK-shaped reply (identity, authorization and outcome unverified)",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.46, "bounded-resp2-reply-correlation");
                    confidence.AddEvidence(0.28, "two-errors-then-ok-distinct-connections");
                    confidence.AddCorrelation(0.22, "same-client-server-ordered-five-minute-window");
                }, count: 3, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        internal static bool IsApprovedClient(string client, ApprovedAssetRegistry approvals)
            => approvals.HasApprovedAdminHosts && approvals.IsAdminHost(client);

        private bool Observe(string key, int port, Guid id, bool isError,
            DateTime now, out bool suppressed)
        {
            suppressed = false;
            lock (_gate)
            {
                if (!_pairs.TryGetValue(key, out var bucket))
                {
                    // A +OK without prior correlated errors is not a sequence.
                    if (!isError)
                        return false;
                    if (_pairs.Count >= MaxPairs)
                    {
                        var stale = new List<string>();
                        foreach (var entry in _pairs)
                            if (now >= entry.Value.LastAt && now - entry.Value.LastAt > Cooldown)
                                stale.Add(entry.Key);
                        foreach (var old in stale)
                            _pairs.Remove(old);
                        if (_pairs.Count >= MaxPairs)
                            return false;
                    }
                    bucket = new Bucket { LastAt = now };
                    _pairs.Add(key, bucket);
                }

                if (now < bucket.LastAt || bucket.Seen.ContainsKey(id))
                    return false;

                var expiredIds = new List<Guid>();
                foreach (var entry in bucket.Seen)
                    if (now >= entry.Value && now - entry.Value > Window)
                        expiredIds.Add(entry.Key);
                foreach (var old in expiredIds)
                    bucket.Seen.Remove(old);

                var expiredPorts = new List<int>();
                foreach (var entry in bucket.ErrorPorts)
                    if (now >= entry.Value && now - entry.Value > Window)
                        expiredPorts.Add(entry.Key);
                foreach (var old in expiredPorts)
                    bucket.ErrorPorts.Remove(old);

                if (bucket.Seen.Count >= MaxIdsPerPair)
                    return false;
                if (isError && !bucket.ErrorPorts.ContainsKey(port)
                    && bucket.ErrorPorts.Count >= MaxPortsPerPair)
                    return false;

                bucket.Seen.Add(id, now);
                bucket.LastAt = now;
                if (isError)
                {
                    // A second packet on one connection never advances distinctness.
                    if (!bucket.ErrorPorts.ContainsKey(port))
                        bucket.ErrorPorts.Add(port, now);
                    return false;
                }

                if (bucket.ErrorPorts.ContainsKey(port) || bucket.ErrorPorts.Count < 2)
                    return false;

                DateTime latestError = DateTime.MinValue;
                foreach (var time in bucket.ErrorPorts.Values)
                    if (time > latestError)
                        latestError = time;
                if (now < latestError || now - latestError > FollowUp)
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

        private static bool TryPrivate(string? value, out string normalized)
        {
            normalized = string.Empty;
            if (!IPAddress.TryParse(value, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork)
                return false;
            var b = ip.GetAddressBytes();
            if (!(b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31
                || b[0] == 192 && b[1] == 168))
                return false;
            normalized = ip.ToString();
            return true;
        }

        private static bool TryPublic(string? value, out string normalized)
        {
            normalized = string.Empty;
            if (!NetworkBatch226230Evidence.Public(value)
                || !IPAddress.TryParse(value, out var ip)
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
