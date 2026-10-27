// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R159_SpringActuatorExposureProbeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R159_SpringActuatorExposureProbeRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R159",
            Name: "Spring Actuator Exposure Probe",
            Category: "HttpApi",
            Description: "Detects cross-boundary probes to sensitive Spring Actuator endpoints while suppressing benign health and info checks.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R159.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R159",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "matched_conditions", "http.path" },
            positiveConditions: new[]
            {
                "The flow must cross an internal/external boundary.",
                "The request must target a sensitive Spring Actuator endpoint such as env, heapdump, or jolokia.",
                "Health and info-only actuator checks should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on /actuator/health or /actuator/info.",
                "Do not alert on non-actuator application URLs."
            },
            minimumConfidence: 78,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host+path",
            falsePositives: new[]
            {
                "Authorized support workflows may query actuator metrics or env endpoints during incident response or maintenance."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive sensitive actuator endpoint sample",
                "negative actuator health sample"
            });

        public R159_SpringActuatorExposureProbeRule()
            : base(Rule, Profile)
        {
        }

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch156165Evidence.Http(record) || !HasMethod(record, "GET", "HEAD") || !NetworkBatch156165Evidence.Actuator(record))
                return NoMatch();

            if (!NetworkBatch126130Evidence.CrossBoundary(record, out _, out var inbound) || !inbound)
                return NoMatch();

            var path = HttpPath(record);
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "actuator_sensitive_path,boundary_crossing", "rule"),
                new("http.routeCategory", "actuator_sensitive", "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "A cross-boundary request reached a sensitive Spring Actuator endpoint.",
                "Severity is High because actuator env, heapdump, jolokia, and similar endpoints can expose credentials, runtime internals, or remote management surfaces.",
                "Approved diagnostics and SRE workflows can generate similar requests. Validate whether the source is a sanctioned operator or monitoring path.",
                "Confirm whether the actuator endpoint should be exposed beyond trusted management networks.",
                "Review adjacent attempts to fetch docs, config files, or admin APIs from the same source."));

            if (!_replay.Observe(record, context.TimestampUtc)) return NoMatch();

            return MatchHttpApi(
                context,
                SeverityLevel.High,
                "Sensitive Spring Actuator endpoint probed",
                "SpringActuatorExposure",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.32, "sensitive-actuator-path");
                    confidence.AddEvidence(0.20, "boundary-crossing");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{path}");
        }
    }
}
