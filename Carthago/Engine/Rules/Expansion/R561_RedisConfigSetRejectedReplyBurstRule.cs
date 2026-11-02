// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.
// File: Engine/Rules/Expansion/R561_RedisConfigSetRejectedReplyBurstRule.cs
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Correlates multiple independently captured RESP2 error replies to first-command
    /// CONFIG SET attempts on distinct TCP connections. An error reply is not proof
    /// of unauthorized access, authenticated Redis identity or a configuration change.
    /// </summary>
    public sealed class R561_RedisConfigSetRejectedReplyBurstRule : DatabaseServiceExposurePrecisionDetectionRuleBase
    {
        private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);
        private const int MaxPairs = 1024;
        private const int MaxPortsPerPair = 32;
        private const int MaxIdsPerPair = 96;

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R561",
            Name: "Repeated Rejected Redis CONFIG SET Requests",
            Category: "DatabaseServiceExposure",
            Description: "Three distinct TCP connections from one public client to one private Redis endpoint yield correlated RESP2 errors within five minutes; no authentication or exploit outcome inferred.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R561.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R561",
            Name = "Repeated Rejected Redis CONFIG SET Requests",
            Category = "DatabaseServiceExposure",
            Description = "Correlated rejected Redis CONFIG SET request burst, not a successful configuration change.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination_or_host", "protocol_or_port" },
            EvidenceFields = new[] { "redis.reply_shape", "redis.distinct_connections", "matched_conditions", "count", "window_seconds" },
            PositiveConditions = new[]
            {
                "PacketHandler must observe a complete first RESP2 CONFIG SET request after TCP SYN, an eligible SYN-ACK and an in-order first RESP2 error reply.",
                "Three distinct client ephemeral ports from one public IPv4 client to one RFC1918 Redis server must yield correlated errors in five minutes.",
                "Only unique packet IDs, coherent reverse TCP/6379 metadata and monotonic timestamps contribute."
            },
            NegativeConditions = new[]
            {
                "Reject +OK, uncorrelated errors, ordinary Redis traffic, TLS, missing handshake, port/Info-only guesses and contradictory fields.",
                "Do not infer authenticated identity, an authorization violation, a specific error code, persistent config changes or exploitation.",
                "Suppress configured approved admin hosts; absence of an allowlist does not establish unauthorized status."
            },
            FalsePositives = new[]
            {
                "Legitimate administrators and automation can retry invalid CONFIG SET parameters or permissions across fresh connections.",
                "NAT, Redis proxies, packet loss and incomplete TCP visibility can distort client identity and counts."
            },
            MinimumConfidence = 86,
            WindowThreshold = 3,
            Window = TimeSpan.FromMinutes(5),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "public_client+private_redis_server+distinct_tcp_client_ports",
            TuningKnobs = new[] { "Mode", "ApprovedAdminHosts", "MaintenanceWindows" },
            RequiredTests = new[]
            {
                "raw TCP producer correlated-error positive and +OK/uncorrelated negatives",
                "benign retries, mixed sources, missing SYN-ACK and malformed RESP negatives",
                "forged labels, duplicate IDs, out-of-order and time-window cases",
                "threshold, cooldown, concurrent evaluation and bounded state",
                "privacy, approved-source suppression and Shadow confidence invariants"
            }
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        private sealed class Bucket
        {
            internal readonly Dictionary<int, DateTime> Ports = new();
            internal readonly Dictionary<Guid, DateTime> Seen = new();
            internal DateTime LastAt;
            internal DateTime? LastEmission;
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, Bucket> _pairs = new(StringComparer.Ordinal);

        public R561_RedisConfigSetRejectedReplyBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (r.Id == Guid.Empty
                || !r.RedisRespConfigSetReplyErrorObserved
                || r.RedisRespConfigSetReplyOkObserved || r.RedisRespConfigSetRequestObserved
                || !r.IsTcp || r.IsUdp || r.IsQuic || r.IpVersion != 4
                || !string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(r.ApplicationProtocol, "redis.resp2", StringComparison.Ordinal)
                || r.SourcePort != 6379
                || r.DestinationPort is null or < 1024 or > 65535 or 6379
                || r.L4Len is null or < 5 or > 512
                || r.Length < r.L4Len.Value + 40
                || r.Sni != null || r.TlsVersion != null || r.Alpn != null
                || r.HttpHost != null || r.HttpUri != null || r.HttpMethod != null
                || r.HttpRequestHeaders != null || r.DnsQname != null
                || r.DnsQtype != null || r.DnsRcode != null || r.DnsAnswers != null
                || !TryPrivate(r.Source, out var server)
                || !TryPublic(r.Destination, out var client))
                return NoMatch();

            // An explicitly approved administrator is a known benign lookalike.
            // An empty policy does not mean the client is unauthorized.
            var approvals = ApprovedAssetRegistry.Current;
            if (IsApprovedClient(client, approvals))
                return NoMatch();

            if (!Observe(client + "|" + server, r.DestinationPort.Value, r.Id,
                    context.TimestampUtc, out var suppressed))
                return NoMatch();
            if (suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("redis.reply_shape", "resp2.error-after-config-set-request", "packet-handler-correlator"),
                new DetectionEvidenceItem("redis.distinct_connections", "3", "rule"),
                new DetectionEvidenceItem("matched_conditions", "same_public_client,same_private_server,three_distinct_tcp_client_ports", "rule"),
                new DetectionEvidenceItem("count", "3", "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Repeated correlated Redis CONFIG SET error replies across three connections (outcomes and authorization unknown)",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.46, "bounded-resp2-request-error-correlation");
                    confidence.AddEvidence(0.28, "three-distinct-connection-ports");
                    confidence.AddCorrelation(0.22, "same-client-server-five-minute-window");
                }, count: 3, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        internal static bool IsApprovedClient(string client, ApprovedAssetRegistry approvals)
            => approvals.HasApprovedAdminHosts && approvals.IsAdminHost(client);

        private bool Observe(string key, int port, Guid id, DateTime now, out bool suppressed)
        {
            suppressed = false;
            lock (_gate)
            {
                if (!_pairs.TryGetValue(key, out var bucket))
                {
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

                var oldIds = new List<Guid>();
                foreach (var entry in bucket.Seen)
                    if (now >= entry.Value && now - entry.Value > Window)
                        oldIds.Add(entry.Key);
                foreach (var old in oldIds)
                    bucket.Seen.Remove(old);

                var oldPorts = new List<int>();
                foreach (var entry in bucket.Ports)
                    if (now >= entry.Value && now - entry.Value > Window)
                        oldPorts.Add(entry.Key);
                foreach (var old in oldPorts)
                    bucket.Ports.Remove(old);

                if (bucket.Seen.Count >= MaxIdsPerPair)
                    return false;
                if (!bucket.Ports.ContainsKey(port) && bucket.Ports.Count >= MaxPortsPerPair)
                    return false;

                bucket.Seen.Add(id, now);
                bucket.Ports[port] = now;
                bucket.LastAt = now;
                if (bucket.Ports.Count < 3)
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
