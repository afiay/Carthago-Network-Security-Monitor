// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R162_RedisMemcachedWebProbeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R162_RedisMemcachedWebProbeRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R162",
            Name: "Redis Memcached Web Probe",
            Category: "HttpApi",
            Description: "Detects cross-boundary web probes aimed at Redis or Memcached administration surfaces instead of generic stats endpoints.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R162.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R162",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "matched_conditions", "http.path", "network.destinationPort" },
            positiveConditions: new[]
            {
                "The flow must cross an internal/external boundary.",
                "The request must target Redis or Memcached-like ports or services with explicit stats or flush style probe indicators.",
                "Generic web stats endpoints should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on ordinary /stats pages that lack Redis or Memcached context.",
                "Do not alert on non-database web traffic."
            },
            minimumConfidence: 72,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host+path",
            falsePositives: new[]
            {
                "Approved cache administration tooling may legitimately access Redis or Memcached monitoring endpoints."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive redis or memcached probe sample",
                "negative generic stats endpoint sample"
            });

        public R162_RedisMemcachedWebProbeRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasHttpContext(record) || !IsRedisMemcachedProbe(record))
                return NoMatch();

            if (!IsCrossBoundary(record, out _, out _))
                return NoMatch();

            var path = HttpPath(record);
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "redis_or_memcached_context,boundary_crossing", "rule"),
                new("http.path", string.IsNullOrWhiteSpace(path) ? "/" : path, "http"),
                new("network.destinationPort", (record.DestinationPort ?? 0).ToString(System.Globalization.CultureInfo.InvariantCulture), "network")
            };
            evidenceItems.AddRange(AnalystContext(
                "A cross-boundary request carried Redis or Memcached probe semantics such as stats or flush commands.",
                "Severity is Medium because cache administration surfaces can leak data structures or allow destructive cache operations.",
                "Approved cache administration and troubleshooting tools may query these endpoints.",
                "Confirm whether the target cache surface is expected to be reachable from the requesting source.",
                "Review for follow-on configuration, credential, or backup file probes from the same source."));

            return MatchHttpApi(
                context,
                SeverityLevel.Medium,
                "Redis/Memcached web probe observed",
                "CacheAdminProbe",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "redis-or-memcached-context");
                    confidence.AddEvidence(0.16, "boundary-crossing");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{path}");
        }
    }
}
