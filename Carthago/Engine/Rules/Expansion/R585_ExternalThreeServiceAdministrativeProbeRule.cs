// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.
using System;
using System.Collections.Generic;
using System.Net;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Three independently classified administrative requests across HTTP, Redis
    /// and SMB2 from one public peer to the same RFC1918 host. Request-only evidence.
    /// </summary>
    public sealed class R585_ExternalThreeServiceAdministrativeProbeRule
        : DatabaseServiceExposurePrecisionDetectionRuleBase
    {
        private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);
        private const int MaxPairs = 512;
        private const int MaxIdsPerPair = 128;

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R585",
            Name: "External Three-Service Administrative Request Probe",
            Category: "DatabaseServiceExposure",
            Description: "One public IPv4 peer issues classified default HTTP Basic admin, Redis CONFIG SET and SMB2 WRITE requests to the same private host within five minutes; no successful access is inferred.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R585.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R585",
            Name = "External Three-Service Administrative Request Probe",
            Category = "DatabaseServiceExposure",
            Description = "Three distinct parser-backed administrative request classes from the same public client to one private host.",
            Severity = SeverityLevel.High,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "destination_or_host", "protocol_or_port" },
            EvidenceFields = new[] { "http.defaultBasicObserved", "redis.configSetRequestObserved", "smb.writeRequestObserved", "matched_conditions", "count", "window_seconds", "outcome" },
            PositiveConditions = new[]
            {
                "A public client sends a parsed known-default HTTP Basic admin request to a private host.",
                "The same client sends a parsed Redis RESP2 CONFIG SET request to that exact private host.",
                "The same client sends a bounded SMB2 WRITE request to that exact private host within five minutes; all three independent service classes are required."
            },
            NegativeConditions = new[]
            {
                "Reject any two-service combination, port-only claims, ordinary credentials, Redis PING, SMB2 CREATE, wrong clients or hosts.",
                "Reject duplicated IDs, out-of-order timestamps, stale windows, reserved endpoints and contradictory transport/application fields.",
                "No authentication, file write, Redis configuration change, compromise or CVE outcome is inferred."
            },
            FalsePositives = new[]
            {
                "Authorized vulnerability assessment or cross-service provisioning can generate all three request types.",
                "NAT, proxies, segmentation, TLS and incomplete capture can hide or confound true peer identity and service coverage."
            },
            MinimumConfidence = 90,
            WindowThreshold = 3,
            Window = Window,
            Cooldown = Cooldown,
            DistinctBy = "exact_public_client+exact_private_host+three_distinct_service_request_classes",
            TuningKnobs = new[] { "Mode", "ApprovedAdminHosts", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "three classified services positive and two-service negative",
                "wrong client/host, ordinary operations, reserved endpoints and contradictory metadata",
                "unique IDs, strict ordering, expiry, bounded memory and cooldown",
                "fixed redacted evidence and no outcome inference",
                "Candidate Shadow confidence floor and registry uniqueness"
            }
        });

        private sealed class PairState
        {
            internal readonly HashSet<Guid> Seen = new();
            internal DateTime First;
            internal DateTime Latest;
            internal DateTime? LastEmission;
            internal int ServiceMask;
        }

        private readonly object _gate = new();
        private readonly Dictionary<string, PairState> _pairs = new(StringComparer.Ordinal);
        public R585_ExternalThreeServiceAdministrativeProbeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!TryClassify(r, out var client, out var server, out var bit))
                return NoMatch();
            var approvals = ApprovedAssetRegistry.Current;
            if (approvals.HasApprovedAdminHosts &&
                (approvals.IsAdminHost(client) || approvals.IsAdminHost(server)))
                return NoMatch();

            var outcome = Observe(client + "|" + server, r.Id, context.TimestampUtc, bit);
            if (outcome == FanoutObservation.None) return NoMatch();
            if (outcome == FanoutObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("http.defaultBasicObserved", "true", "packet-handler-http-parser"),
                new DetectionEvidenceItem("redis.configSetRequestObserved", "true", "packet-handler-redis-parser"),
                new DetectionEvidenceItem("smb.writeRequestObserved", "true", "bounded-smb2-classifier"),
                new DetectionEvidenceItem("matched_conditions", "same_public_client,exact_private_host,three_distinct_services", "rule"),
                new DetectionEvidenceItem("count", "3", "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule"),
                new DetectionEvidenceItem("outcome", "requests_only_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "Three different administrative request classes reached one internal host; all outcomes unknown",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.30, "classified-default-http-basic-admin-request");
                    confidence.AddEvidence(0.30, "classified-redis-config-set-request");
                    confidence.AddEvidence(0.24, "classified-smb2-write-request");
                    confidence.AddCorrelation(0.15, "same-client-host-three-services-five-minute-window");
                }, count: 3, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        private static bool TryClassify(TrafficRecord r, out string client, out string server, out int bit)
        {
            client = server = string.Empty;
            bit = 0;
            if (!CrossBoundaryRequestEvidence.TryPair(r, publicToPrivate: true, out client, out _)
                || !IPAddress.TryParse(r.Destination, out var address))
                return false;
            server = address.ToString();

            if (CrossBoundaryRequestEvidence.Tcp(r, 40, 4096)
                && r.HttpBasicDefaultCredentialObserved
                && CrossBoundaryRequestEvidence.NoRedisParserFlags(r)
                && string.Equals(r.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                && r.DestinationPort is 80 or 8080 or 8000 or 8008 or 8888
                && r.HttpMethod is "GET" or "POST"
                && IsAdminPath(r.HttpUri)
                && r.HttpHost is { Length: > 0 and <= 253 }
                && r.HttpRequestHeaders?.Contains("Authorization: [REDACTED]", StringComparison.OrdinalIgnoreCase) == true)
                bit = 1;
            else if (CrossBoundaryRequestEvidence.Tcp(r, 6, 256)
                && r.DestinationPort == 6379
                && string.Equals(r.ApplicationProtocol, "redis.resp2", StringComparison.Ordinal)
                && r.RedisRespConfigSetRequestObserved
                && CrossBoundaryRequestEvidence.NoHttpOrConflictingParserFlags(r))
                bit = 2;
            else if (CrossBoundaryRequestEvidence.Tcp(r, 117, 4096)
                && r.DestinationPort == 445
                && string.Equals(r.ApplicationProtocol, "smb2.write.request", StringComparison.Ordinal)
                && CrossBoundaryRequestEvidence.NoHttpOrConflictingParserFlags(r)
                && CrossBoundaryRequestEvidence.NoRedisParserFlags(r))
                bit = 4;
            return bit != 0;
        }

        private FanoutObservation Observe(string key, Guid id, DateTime now, int bit)
        {
            lock (_gate)
            {
                if (!_pairs.TryGetValue(key, out var state))
                {
                    if (_pairs.Count >= MaxPairs)
                    {
                        var expired = new List<string>();
                        foreach (var pair in _pairs)
                            if (now >= pair.Value.Latest && now - pair.Value.Latest > Cooldown)
                                expired.Add(pair.Key);
                        foreach (var stale in expired) _pairs.Remove(stale);
                        if (_pairs.Count >= MaxPairs) return FanoutObservation.None;
                    }
                    state = new PairState { First = now };
                    _pairs.Add(key, state);
                }
                if (now <= state.Latest || state.Seen.Contains(id))
                    return FanoutObservation.None;
                if (now - state.First > Window)
                {
                    state.Seen.Clear();
                    state.ServiceMask = 0;
                    state.First = now;
                }
                if (state.Seen.Count >= MaxIdsPerPair) return FanoutObservation.None;
                state.Seen.Add(id);
                state.Latest = now;
                state.ServiceMask |= bit;
                if (state.ServiceMask != 7) return FanoutObservation.None;
                state.ServiceMask = 0;
                state.First = now;
                if (state.LastEmission.HasValue && now >= state.LastEmission.Value
                    && now - state.LastEmission.Value < Cooldown)
                    return FanoutObservation.Suppressed;
                state.LastEmission = now;
                return FanoutObservation.Match;
            }
        }

        private static bool IsAdminPath(string? uri)
        {
            if (string.IsNullOrEmpty(uri) || uri.Length > 256 || uri[0] != '/') return false;
            var q = uri.IndexOf('?');
            var path = q < 0 ? uri : uri.Substring(0, q);
            return path.Equals("/admin", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/admin/", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/login", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/login.cgi", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/setup.cgi", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/cgi-bin/luci/", StringComparison.OrdinalIgnoreCase);
        }
    }
}
