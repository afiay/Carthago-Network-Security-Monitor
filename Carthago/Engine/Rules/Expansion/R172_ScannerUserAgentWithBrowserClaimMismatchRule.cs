// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R172_ScannerUserAgentWithBrowserClaimMismatchRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R172_ScannerUserAgentWithBrowserClaimMismatchRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R172",
            Name: "Scanner User Agent With Browser Claim Mismatch",
            Category: "HttpApi",
            Description: "Detects HTTP user agents that simultaneously identify as known scanners and as browsers, rather than every scanner user agent.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R172.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R172",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Payload },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "matched_conditions", "http.user_agent" },
            positiveConditions: new[]
            {
                "The request must have a concrete HTTP user agent.",
                "The user agent must simultaneously claim a known scanner and a browser-like identity.",
                "Pure browser traffic or pure scanner identification without a mismatch should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on normal browsers.",
                "Do not alert on scanners that make no attempt to masquerade as browsers."
            },
            minimumConfidence: 68,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+host",
            falsePositives: new[]
            {
                "Some sanctioned scanners deliberately imitate browser user agents to test bypass logic."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive scanner browser mismatch sample",
                "negative normal browser sample"
            });

        public R172_ScannerUserAgentWithBrowserClaimMismatchRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasHttpContext(record) || !HasScannerUserAgentWithBrowserClaimMismatch(record))
                return NoMatch();

            if (!IsCrossBoundary(record, out _, out _))
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "scanner_user_agent,browser_claim_mismatch,boundary_crossing", "rule"),
                new("http.user_agent", ShortText(UserAgent(record)), "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "The HTTP user agent simultaneously identified as a known scanner and as a browser-like client.",
                "Severity is Low because this is primarily reconnaissance signal, but it can indicate evasive scanning behavior.",
                "Approved scanners often mimic browsers deliberately. Validate whether the source belongs to an authorized assessment workflow.",
                "Confirm whether the source address or process maps to an approved scanner.",
                "Review adjacent admin-path, upload, request smuggling, or docs-probe traffic from the same source."));

            return MatchHttpApi(
                context,
                SeverityLevel.Low,
                "Scanner user agent masquerading as browser observed",
                "ScannerUserAgentMismatch",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.18, "scanner-user-agent");
                    confidence.AddEvidence(0.18, "browser-claim-mismatch");
                    confidence.AddEvidence(0.10, "boundary-crossing");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}");
        }
    }
}
