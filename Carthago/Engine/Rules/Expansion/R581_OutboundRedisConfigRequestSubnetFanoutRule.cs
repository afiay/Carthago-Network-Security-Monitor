// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed.
using System;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>Private client attempts RESP2 CONFIG SET across three public /24 networks.</summary>
    public sealed class R581_OutboundRedisConfigRequestSubnetFanoutRule
        : DatabaseServiceExposurePrecisionDetectionRuleBase
    {
        private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R581",
            Name: "Outbound Redis CONFIG SET Request Subnet Fanout",
            Category: "DatabaseServiceExposure",
            Description: "One private client sends parsed Redis CONFIG SET requests to three distinct public /24 networks within five minutes; no server reply is required.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R581.Enabled",
            EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R581", Name = "Outbound Redis CONFIG SET Request Subnet Fanout",
            Category = "DatabaseServiceExposure",
            Description = "Parser-observed Redis configuration commands fan out from an internal client to three public /24 networks.",
            Severity = SeverityLevel.High,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "destination_or_host", "protocol_or_port" },
            EvidenceFields = new[] { "redis.operation", "matched_conditions", "count", "window_seconds", "redis.outcome" },
            PositiveConditions = new[]
            {
                "Bounded packet producer identifies a complete RESP2 CONFIG SET client request on TCP/6379.",
                "One RFC1918 source contacts three distinct globally routable public destination /24 networks within five minutes.",
                "Retain unique packet IDs, valid TCP/IP metadata, monotonic timestamps and bounded state."
            },
            NegativeConditions = new[]
            {
                "Reject PING, reply-only, TLS, one destination /24, private and reserved destinations, port-only and Info-only claims.",
                "Reject mixed sources, stale observations, duplicates, contradictory metadata and approved admin source hosts.",
                "Do not infer confirmed external Redis identity, successful reconfiguration or malicious intent."
            },
            FalsePositives = new[]
            {
                "Approved Redis fleet management, cloud migration and testing can use external providers.",
                "Network address translation, TCP segmentation and missing policy inventory can distort classification."
            },
            MinimumConfidence = 86, WindowThreshold = 3, Window = Window,
            Cooldown = Cooldown, DistinctBy = "private_client+distinct_public_destination_24",
            TuningKnobs = new[] { "Mode", "ApprovedAdminHosts", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "parsed outbound CONFIG SET versus PING/reply", "three public /24s versus repeats",
                "reserved IP, duplicate and mixed source negative controls",
                "expiry, order, cooldown, bound and concurrency",
                "privacy, Candidate Shadow profile and registry uniqueness"
            }
        });
        private readonly CrossBoundaryRequestFanoutWindow _window = new();

        public R581_OutboundRedisConfigRequestSubnetFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!CrossBoundaryRequestEvidence.Tcp(r, 6, 256)
                || r.DestinationPort != 6379
                || !string.Equals(r.ApplicationProtocol, "redis.resp2", StringComparison.Ordinal)
                || !r.RedisRespConfigSetRequestObserved
                || !CrossBoundaryRequestEvidence.NoHttpOrConflictingParserFlags(r)
                || !CrossBoundaryRequestEvidence.TryPair(r, publicToPrivate: false,
                    out var client, out var target24))
                return NoMatch();
            var approvals = ApprovedAssetRegistry.Current;
            if (approvals.HasApprovedAdminHosts && approvals.IsAdminHost(client))
                return NoMatch();
            var observation = _window.Observe(client, target24, r.Id, context.TimestampUtc);
            if (observation == FanoutObservation.None) return NoMatch();
            if (observation == FanoutObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("redis.operation", "resp2.config_set.request", "packet-handler"),
                new DetectionEvidenceItem("matched_conditions", "private_to_public,three_distinct_public_24s", "rule"),
                new DetectionEvidenceItem("count", "3", "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule"),
                new DetectionEvidenceItem("redis.outcome", "request_only_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "Outbound Redis CONFIG SET request fanout (server outcome unverified)",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.46, "parser-confirmed-redis-config-request");
                    confidence.AddEvidence(0.24, "private-to-public-boundary");
                    confidence.AddCorrelation(0.19, "three-distinct-public-24s");
                }, count: 3, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
