// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R176_HostHeaderInjectionIndicatorRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R176_HostHeaderInjectionIndicatorRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R176",
            Name: "Host Header Injection Indicator",
            Category: "HttpApi",
            Description: "Detects Host or forwarded-host headers that target internal or mismatched hosts instead of alerting on every proxy-related header.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R176.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R176",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Payload },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "matched_conditions", "host_header.detail" },
            positiveConditions: new[]
            {
                "The request must contain Host or forwarding headers with internal or mismatched target semantics.",
                "Rewrite-target abuse and internal Host header targeting should be treated as stronger signals than ordinary reverse-proxy headers.",
                "Benign forwarding headers that align with the request host should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on normal reverse-proxy header usage.",
                "Do not alert when Host and forwarded-host values stay within the same trust boundary."
            },
            minimumConfidence: 74,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host+detail",
            falsePositives: new[]
            {
                "Complex ingress or reverse-proxy chains can legitimately rewrite host headers across trusted internal domains."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive suspicious forwarded host sample",
                "negative ordinary proxy host header sample"
            });

        public R176_HostHeaderInjectionIndicatorRule()
            : base(Rule, Profile)
        {
        }

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch176180Evidence.Http(record) || !NetworkBatch176180Evidence.HostAbuse(record, out var detail) || !_replay.Observe(record, context.TimestampUtc))
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "host_or_forwarded_header_abuse", "rule"),
                new("host_header.detail", detail, "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "A Host-related HTTP header targeted an internal or mismatched host boundary.",
                "Severity is Medium because Host header injection can influence routing, password reset links, cache keys, and SSRF-style back-end behaviors.",
                "Trusted ingress layers can legitimately rewrite host headers. Validate whether the request passed through an approved proxy chain.",
                "Confirm whether the header values align with expected ingress or reverse-proxy behavior.",
                "Review adjacent open redirect, request smuggling, and admin API activity from the same source."));

            return MatchHttpApi(
                context,
                SeverityLevel.Medium,
                "Suspicious Host header behavior observed",
                "HostHeaderInjection",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "host-or-forwarded-header-abuse");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{detail}");
        }
    }
}
