// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R164_OpenRedirectParameterAbuseRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R164_OpenRedirectParameterAbuseRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R164",
            Name: "Open Redirect Parameter Abuse",
            Category: "HttpApi",
            Description: "Detects redirect-style query parameters that point to suspicious external or internal targets instead of matching every redirect_uri string.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R164.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R164",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Payload },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "matched_conditions", "query.parameter", "redirect.target" },
            positiveConditions: new[]
            {
                "The request URI must contain a redirect-style parameter.",
                "The redirect target must resolve to an explicit suspicious destination such as a foreign host, localhost, or plain HTTP URL.",
                "Ordinary authentication redirect_uri flows should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on same-site redirect or return parameters.",
                "Do not alert on expected OIDC or SAML callback redirect_uri values."
            },
            minimumConfidence: 74,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host+parameter",
            falsePositives: new[]
            {
                "Legacy authentication brokers and multi-domain applications can legitimately carry redirect parameters."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive foreign redirect parameter sample",
                "negative same-site oidc redirect sample"
            });

        public R164_OpenRedirectParameterAbuseRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasHttpContext(record) || !TryGetSuspiciousRedirectTarget(record, out var parameterName, out var target))
                return NoMatch();

            var matchedConditions = new List<string> { "redirect_parameter", "suspicious_target" };
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule"),
                new("query.parameter", parameterName, "http"),
                new("redirect.target", ShortText(target), "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "A redirect-style query parameter pointed to a suspicious target host or insecure absolute URL.",
                "Severity is Medium because open redirects are commonly chained for phishing, token leakage, and SSRF pivots.",
                "Some multi-domain apps or auth brokers legitimately use redirect parameters. Validate whether the target is approved for the requesting application.",
                "Confirm whether the redirect target belongs to an approved application domain or trust boundary.",
                "Review adjacent token, callback, or phishing-related traffic from the same source."));

            return MatchHttpApi(
                context,
                SeverityLevel.Medium,
                "Suspicious open redirect target observed",
                "OpenRedirectAbuse",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "redirect-parameter");
                    confidence.AddEvidence(0.24, "suspicious-target");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{parameterName}");
        }
    }
}
