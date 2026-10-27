// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R156_JwtNoneAlgorithmIndicatorRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R156_JwtNoneAlgorithmIndicatorRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R156",
            Name: "JWT None Algorithm Indicator",
            Category: "HttpApi",
            Description: "Detects JWT material whose decoded header explicitly uses the none algorithm instead of loose alg:none text matching.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R156.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R156",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Payload },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "matched_conditions", "jwt.source" },
            positiveConditions: new[]
            {
                "The HTTP record must contain JWT-like material in a query parameter, Authorization header, or parser info.",
                "The JWT header must decode successfully and explicitly specify alg=none.",
                "Free-form text alone without decodable JWT context should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on normal signed JWTs.",
                "Do not alert on AnyText-only references to alg:none with no JWT material."
            },
            minimumConfidence: 80,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(15),
            distinctBy: "host",
            falsePositives: new[]
            {
                "Security test fixtures and intentionally malformed lab tokens can match. Validate whether the token came from a test harness."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive decodable jwt none token sample",
                "negative signed jwt sample"
            });

        public R156_JwtNoneAlgorithmIndicatorRule()
            : base(Rule, Profile)
        {
        }

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch156165Evidence.Http(record) || !NetworkBatch156165Evidence.JwtNone(record, out var source))
                return NoMatch();

            var matchedConditions = new List<string> { "jwt_context", "decoded_alg_none" };
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule"),
                new("jwt.source", source, "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "The HTTP record carried JWT material whose decoded header explicitly used the none algorithm.",
                "Severity is High because alg=none enables signature bypass patterns and is rarely legitimate in production traffic.",
                "Lab harnesses, fuzzing, and security validation workflows may deliberately exercise alg=none tokens.",
                "Review the source request path, headers, and target application behavior to confirm whether the token was accepted or rejected.",
                "Check for adjacent authentication bypass, admin API access, or open redirect activity from the same source."));

            if (!_replay.Observe(record, context.TimestampUtc)) return NoMatch();

            return MatchHttpApi(
                context,
                SeverityLevel.High,
                "JWT with none algorithm observed",
                "JwtNoneAlgorithm",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "jwt-context");
                    confidence.AddEvidence(0.34, "decoded-alg-none");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{source}");
        }
    }
}
