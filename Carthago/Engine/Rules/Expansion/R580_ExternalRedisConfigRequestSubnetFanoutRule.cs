// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed.
using System;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>Public client attempts RESP2 CONFIG SET on three private /24 networks.</summary>
    public sealed class R580_ExternalRedisConfigRequestSubnetFanoutRule
        : DatabaseServiceExposurePrecisionDetectionRuleBase
    {
        private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R580",
            Name: "External Redis CONFIG SET Request Subnet Fanout",
            Category: "DatabaseServiceExposure",
            Description: "One public client sends parser-observed RESP2 CONFIG SET requests to three distinct private /24 networks in five minutes; replies and outcome are unknown.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R580.Enabled",
            EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R580", Name = "External Redis CONFIG SET Request Subnet Fanout",
            Category = "DatabaseServiceExposure",
            Description = "Three distinct RFC1918 target /24s receive request-only Redis CONFIG SET attempts from one public source.",
            Severity = SeverityLevel.High,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "destination_or_host", "protocol_or_port" },
            EvidenceFields = new[] { "redis.operation", "matched_conditions", "count", "window_seconds", "redis.outcome" },
            PositiveConditions = new[]
            {
                "PacketHandler classifies a bounded RESP2 CONFIG SET request on client-to-server TCP/6379, with handshake provenance.",
                "The same globally routable public IPv4 source sends requests to three distinct RFC1918 /24 destination networks in five minutes.",
                "Require coherent IPv4/TCP fields, distinct packet identifiers, monotonic timestamps and bounded state."
            },
            NegativeConditions = new[]
            {
                "Reject PING, +OK, error replies, TLS, Info-only and port-only claims, repeated hosts in one /24 and mixed clients.",
                "Reject reserved endpoints, contradictions, duplicates, stale windows and explicitly approved administration endpoints.",
                "Do not infer authentication, command acceptance, configuration changes or Redis server identity from a request."
            },
            FalsePositives = new[]
            {
                "Authorized external security assessments and approved fleet configuration can contact multiple servers.",
                "NAT, proxies, partial TCP capture and missing asset inventory can distort identity or visibility."
            },
            MinimumConfidence = 86, WindowThreshold = 3, Window = Window,
            Cooldown = Cooldown, DistinctBy = "public_client+distinct_private_destination_24",
            TuningKnobs = new[] { "Mode", "ApprovedAdminHosts", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "parsed request positive and PING/reply negative", "three distinct /24 versus same-/24 fanout",
                "source isolation, reserved IP, duplicate, malformed and contradictory metadata",
                "out-of-order, expiry, cooldown, bounded memory and concurrency",
                "redaction, Candidate Shadow mode and unique registry registration"
            }
        });
        private readonly CrossBoundaryRequestFanoutWindow _window = new();

        public R580_ExternalRedisConfigRequestSubnetFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!CrossBoundaryRequestEvidence.Tcp(r, 6, 256)
                || r.DestinationPort != 6379
                || !string.Equals(r.ApplicationProtocol, "redis.resp2", StringComparison.Ordinal)
                || !r.RedisRespConfigSetRequestObserved
                || !CrossBoundaryRequestEvidence.NoHttpOrConflictingParserFlags(r)
                || !CrossBoundaryRequestEvidence.TryPair(r, publicToPrivate: true,
                    out var client, out var target24))
                return NoMatch();
            var approvals = ApprovedAssetRegistry.Current;
            if (approvals.HasApprovedAdminHosts
                && (approvals.IsAdminHost(client) || approvals.IsAdminHost(r.Destination!)))
                return NoMatch();
            var observation = _window.Observe(client, target24, r.Id, context.TimestampUtc);
            if (observation == FanoutObservation.None) return NoMatch();
            if (observation == FanoutObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("redis.operation", "resp2.config_set.request", "packet-handler"),
                new DetectionEvidenceItem("matched_conditions", "public_to_private,three_distinct_private_24s", "rule"),
                new DetectionEvidenceItem("count", "3", "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule"),
                new DetectionEvidenceItem("redis.outcome", "request_only_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "External Redis CONFIG SET request fanout (server outcome unverified)",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.46, "parser-confirmed-redis-config-request");
                    confidence.AddEvidence(0.24, "public-to-private-boundary");
                    confidence.AddCorrelation(0.19, "three-distinct-private-24s");
                }, count: 3, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
