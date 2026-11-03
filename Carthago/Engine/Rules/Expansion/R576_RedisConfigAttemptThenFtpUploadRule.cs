// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Correlates a parser-confirmed known-default HTTP Basic admin request with
    /// a later, independently wire-correlated Redis CONFIG SET OK-shaped reply
    /// for the exact same public client and private server. Neither authentication
    /// nor authorized/persistent configuration change is established.
    /// </summary>
    public sealed class R576_RedisConfigAttemptThenFtpUploadRule
        : DatabaseServiceExposurePrecisionDetectionRuleBase
    {
        private static readonly TimeSpan Window = TimeSpan.FromSeconds(120);
        private static readonly TimeSpan Cooldown = TimeSpan.FromSeconds(600);
        private const int MaxPairs = 512;
        private const int MaxIdsPerPair = 64;

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R576",
            Name: "Redis CONFIG SET Attempt Then FTP Upload Command",
            Category: "DatabaseServiceExposure",
            Description: "Public client issues parsed Redis CONFIG SET request to private server; same server subsequently sends FTP STOR/APPE to that client within 120 seconds, without claiming reply or transfer outcome.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R576.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R576",
            Name = "Redis CONFIG SET Attempt Then FTP Upload Command",
            Category = "DatabaseServiceExposure",
            Description = "Redis CONFIG SET request then outbound FTP upload command for exact public/private peer pair.",
            Severity = SeverityLevel.High,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "destination_or_host", "protocol_or_port", "http_any" },
            EvidenceFields = new[] { "ftp.upload_command_observed", "redis.reply_shape", "redis.config_status", "matched_conditions", "count", "window_seconds" },
            PositiveConditions = new[]
            {
                "PacketHandler classifies FTP STOR/APPE from RFC1918 host to globally routable public IPv4 peer.",
                "PacketHandler internally classifies Redis RESP2 CONFIG SET request from the public client to the private host; no Redis reply required.",
                "Strict Redis-before-FTP order, unique IDs, 120s window, approved-host exclusion, bounded state."
            },
            NegativeConditions = new[]
            {
                "Reject Redis PING, replies without request evidence, FTP RETR/LIST, wrong peers, duplicate IDs and stale windows.",
                "Reject imported/spoofed flags, Info-only or port-only guesses, TLS/QUIC, reserved peers, duplicate IDs, stale windows, saturation and approved admin sources.",
                "Do not claim successful HTTP login, authenticated Redis identity, specific changed parameter, durable change, compromise, exploit or CVE."
            },
            FalsePositives = new[]
            {
                "Approved multi-service provisioning and configuration management can access a web admin console and then Redis CONFIG SET on the same host.",
                "NAT, proxies, incomplete capture, TCP segmentation, HTTPS or Redis TLS can obscure the true client and sequence; absence of an allowlist is not proof of unauthorized activity."
            },
            MinimumConfidence = 90,
            WindowThreshold = 1,
            Window = Window,
            Cooldown = Cooldown,
            DistinctBy = "exact_public_client+exact_private_server+ordered_redis_config_set_error_reply_then_http_default_basic",
            TuningKnobs = new[] { "Mode", "ApprovedAdminHosts", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "parser-backed Redis and FTP positive",
                "FTP read, wrong peer, opposite Redis status and missing handshake",
                "spoofed JSON, reserved addresses, Info-only, missing handshake and contradictory protocol metadata negatives",
                "duplicate packet IDs, reversed/equal time, expiry, seed consumption, cooldown and concurrent duplicates",
                "privacy, bounded state, unique registry registration, Candidate/Shadow/90% invariants"
            }
        };
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        private sealed class PairState
        {
            internal readonly Dictionary<Guid, DateTime> Seen = new();
            internal DateTime Latest;
            internal DateTime? PendingRedis;
            internal DateTime? LastEmission;
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, PairState> _pairs = new(StringComparer.Ordinal);

        public R576_RedisConfigAttemptThenFtpUploadRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!TryQualify(record, out var publicClient, out var privateServer, out var http))
                return NoMatch();

            if (IsApprovedPair(publicClient, privateServer, ApprovedAssetRegistry.Current))
                return NoMatch();

            if (!Observe(publicClient + "|" + privateServer, record.Id,
                    context.TimestampUtc, http, out var suppressed))
                return NoMatch();
            if (suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            // Fixed non-secret labels only. Never include Authorization, URI, Host,
            // Redis parameter/value, raw RESP, Info, or endpoint lists.
            var evidence = new[]
            {
                new DetectionEvidenceItem("ftp.upload_command_observed", "true", "packet-handler-ftp-parser"),
                new DetectionEvidenceItem("redis.reply_shape", "resp2.config_set_request", "packet-handler-correlator"),
                new DetectionEvidenceItem("redis.config_status", "request_only_no_reply_attested", "rule"),
                new DetectionEvidenceItem("matched_conditions", "same_public_client_and_private_server,redis_request_before_ftp,within_120_seconds", "rule"),
                new DetectionEvidenceItem("count", "1", "rule"),
                new DetectionEvidenceItem("window_seconds", "120", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "Ordered Redis CONFIG SET request and FTP upload command; outcomes unverified",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.46, "packet-handler-ftp-upload-command");
                    confidence.AddEvidence(0.31, "syn-anchored-redis-config-set-ok-reply");
                    confidence.AddCorrelation(0.23, "exact-endpoint-redis-request-before-ftp-two-minute-sequence");
                }, count: 1, windowSeconds: 120);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        internal static bool IsApprovedPair(string client, string server, ApprovedAssetRegistry approvals)
            => approvals.HasApprovedAdminHosts
                && (approvals.IsAdminHost(client) || approvals.IsAdminHost(server));

        private static bool TryQualify(TrafficRecord r, out string client, out string server, out bool http)
        {
            client = string.Empty;
            server = string.Empty;
            http = false;
            if (r.Id == Guid.Empty || r.IpVersion != 4 || !r.IsTcp || r.IsUdp || r.IsQuic
                || !string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                || r.L4Len is null or < 5 or > 4096
                || r.Length < r.L4Len.Value + 40
                || r.TlsVersion != null || r.Sni != null || r.Alpn != null
                || r.DnsQname != null || r.DnsQtype != null
                || r.DnsRcode != null || r.DnsAnswers != null)
                return false;

            if (!r.HttpBasicDefaultCredentialObserved && !r.RedisRespConfigSetRequestObserved
                && !r.RedisRespConfigSetReplyOkObserved && !r.RedisRespConfigSetReplyErrorObserved
                && r.DestinationPort == 21 && r.SourcePort is >= 1024 and <= 65535
                && r.L4Len is >= 8 and <= 256 && r.HttpMethod == null && r.HttpUri == null
                && r.HttpHost == null && r.HttpRequestHeaders == null
                && NetworkBatch246250Evidence.FtpUpload(r)
                && TryPrivate(r.Source, out server) && TryPublic(r.Destination, out client))
            { http = true; return true; }

            if (!r.HttpBasicDefaultCredentialObserved
                && r.RedisRespConfigSetRequestObserved
                && !r.RedisRespConfigSetReplyOkObserved
                && !r.RedisRespConfigSetReplyErrorObserved
                && string.Equals(r.ApplicationProtocol, "redis.resp2", StringComparison.Ordinal)
                && r.DestinationPort == 6379
                && r.SourcePort is >= 1024 and <= 65535 and not 6379
                && r.L4Len is >= 6 and <= 256
                && r.HttpMethod == null && r.HttpUri == null
                && r.HttpHost == null && r.HttpRequestHeaders == null
                && TryPublic(r.Source, out client)
                && TryPrivate(r.Destination, out server))
                return true;

            return false;
        }

        private bool Observe(string key, Guid id, DateTime now, bool http, out bool suppressed)
        {
            suppressed = false;
            lock (_gate)
            {
                if (!_pairs.TryGetValue(key, out var state))
                {
                    if (http) return false;
                    if (_pairs.Count >= MaxPairs)
                    {
                        var stale = new List<string>();
                        foreach (var entry in _pairs)
                            if (now >= entry.Value.Latest && now - entry.Value.Latest >= Cooldown)
                                stale.Add(entry.Key);
                        foreach (var old in stale) _pairs.Remove(old);
                        if (_pairs.Count >= MaxPairs) return false;
                    }
                    state = new PairState();
                    _pairs.Add(key, state);
                }

                if (now <= state.Latest || state.Seen.ContainsKey(id))
                    return false;

                var expired = new List<Guid>();
                foreach (var entry in state.Seen)
                    if (now >= entry.Value && now - entry.Value > Cooldown)
                        expired.Add(entry.Key);
                foreach (var old in expired) state.Seen.Remove(old);
                if (state.Seen.Count >= MaxIdsPerPair) return false;

                if (!http)
                {
                    if (state.PendingRedis is null || now - state.PendingRedis.Value > Window)
                        state.PendingRedis = now;
                    state.Seen.Add(id, now);
                    state.Latest = now;
                    return false;
                }

                if (state.PendingRedis is null || now <= state.PendingRedis.Value
                    || now - state.PendingRedis.Value > Window)
                    return false;

                state.Seen.Add(id, now);
                state.Latest = now;
                state.PendingRedis = null;
                if (state.LastEmission.HasValue && now >= state.LastEmission.Value
                    && now - state.LastEmission.Value < Cooldown)
                {
                    suppressed = true;
                    return true;
                }
                state.LastEmission = now;
                return true;
            }
        }

        private static bool IsAdminPath(string? uri)
        {
            if (string.IsNullOrEmpty(uri) || uri.Length > 256 || uri[0] != '/')
                return false;
            var query = uri.IndexOf('?');
            var path = query < 0 ? uri : uri.Substring(0, query);
            return path.Equals("/admin", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/admin/", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/login", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/login.cgi", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/setup.cgi", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/cgi-bin/luci/", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/goform/", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/boaform/", StringComparison.OrdinalIgnoreCase);
        }

        private static bool SafeHost(string? host)
        {
            if (string.IsNullOrWhiteSpace(host) || host.Length > 253)
                return false;
            foreach (var ch in host)
                if (char.IsWhiteSpace(ch) || ch is '@' or '/' or '?' or '#' or '\\')
                    return false;
            return true;
        }

        private static bool TryPrivate(string? value, out string normalized)
        {
            normalized = string.Empty;
            if (!IPAddress.TryParse(value, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork) return false;
            var b = ip.GetAddressBytes();
            if (!(b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31
                || b[0] == 192 && b[1] == 168)) return false;
            normalized = ip.ToString();
            return true;
        }

        private static bool TryPublic(string? value, out string normalized)
        {
            normalized = string.Empty;
            if (!NetworkBatch226230Evidence.Public(value)
                || !IPAddress.TryParse(value, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork) return false;
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
