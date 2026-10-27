// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R165_PhpinfoExposureProbeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R165_PhpinfoExposureProbeRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R165",
            Name: "PHPInfo Exposure Probe",
            Category: "HttpApi",
            Description: "Detects cross-boundary access to concrete phpinfo exposure paths instead of generic info pages.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R165.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R165",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "matched_conditions", "http.path" },
            positiveConditions: new[]
            {
                "The flow must cross an internal/external boundary.",
                "The path must exactly resemble phpinfo exposure locations such as /phpinfo.php.",
                "Generic information pages should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on ordinary /info or help pages.",
                "Do not alert without an exact phpinfo-style path."
            },
            minimumConfidence: 70,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host+path",
            falsePositives: new[]
            {
                "Legacy admin or troubleshooting workflows may intentionally access phpinfo pages."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive phpinfo path sample",
                "negative generic info page sample"
            });

        public R165_PhpinfoExposureProbeRule()
            : base(Rule, Profile)
        {
        }

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch156165Evidence.Http(record) || !HasMethod(record, "GET", "HEAD") || !NetworkBatch156165Evidence.PhpInfo(record))
                return NoMatch();

            if (!NetworkBatch126130Evidence.CrossBoundary(record, out _, out var inbound) || !inbound)
                return NoMatch();

            var path = HttpPath(record);
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "phpinfo_path,boundary_crossing", "rule"),
                new("http.routeCategory", "phpinfo", "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "A cross-boundary request targeted a phpinfo exposure path.",
                "Severity is Low because phpinfo exposure is primarily reconnaissance, but it can disclose environment details, module versions, and filesystem paths.",
                "Support teams may intentionally browse phpinfo during troubleshooting. Validate whether the target host is an approved maintenance target.",
                "Confirm whether the phpinfo page should exist on the target environment.",
                "Review for follow-on .env, .git, backup, or upload-related probes from the same source."));

            if (!_replay.Observe(record, context.TimestampUtc)) return NoMatch();

            return MatchHttpApi(
                context,
                SeverityLevel.Low,
                "phpinfo exposure path requested",
                "PhpInfoProbe",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.22, "phpinfo-path");
                    confidence.AddEvidence(0.14, "boundary-crossing");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{path}");
        }
    }
}
