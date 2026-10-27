// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R127_AdminPortalAccessFromInternetRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R127_AdminPortalAccessFromInternetRule : IdentityAccessPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R127",
            Name: "Admin Portal Access From Internet",
            Category: "IdentityAccess",
            Description: "Detects cross-boundary access to explicit admin portal paths, while suppressing ordinary public login pages and appliance-specific portals handled elsewhere.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R127.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIdentityAccessProfile(
            ruleId: "R127",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "matched_conditions", "http.path" },
            positiveConditions: new[]
            {
                "The request must cross an internal-external boundary.",
                "The HTTP path must clearly indicate an admin portal or management console.",
                "Network-appliance-specific management portals should be handled by the dedicated appliance rule."
            },
            negativeConditions: new[]
            {
                "Do not alert on generic login pages with no admin semantics.",
                "Do not alert on appliance management portals handled by R128."
            },
            minimumConfidence: 72,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Approved SaaS admin consoles or sanctioned internet-facing management portals can match."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive admin portal path sample",
                "negative generic login page sample"
            });

        public R127_AdminPortalAccessFromInternetRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch126130Evidence.HttpRequest(record))
                return NoMatch();

            if (!NetworkBatch126130Evidence.CrossBoundary(record, out var outboundToExternal, out var inboundFromExternal))
                return NoMatch();

            if (!NetworkBatch126130Evidence.AdminPortal(HttpPath(record))
                || NetworkBatch126130Evidence.AppliancePortal(record, HttpPath(record)))
                return NoMatch();

            var path = HttpPath(record);
            var matchedConditions = new List<string> { "admin_portal_path", "cross_boundary" };
            if (outboundToExternal) matchedConditions.Add("outbound_to_external");
            if (inboundFromExternal) matchedConditions.Add("inbound_from_external");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule"),
                new("http.path", "[admin-route]", "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                outboundToExternal
                    ? "An internal client reached an internet-hosted admin portal or management console."
                    : "An external source reached an internal admin portal or management console.",
                "Severity is High because cross-boundary admin portal exposure creates a direct management-plane risk.",
                "Approved internet-facing administration portals can match. Validate whether the portal is sanctioned and properly restricted.",
                "Confirm whether the portal is expected to be reachable across this trust boundary.",
                "Review authentication logs and MFA events tied to the portal and source."));

            return MatchIdentityAccess(
                context,
                SeverityLevel.High,
                "Cross-boundary admin portal access observed",
                "AdminPortal",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "http-context");
                    confidence.AddEvidence(0.24, "admin-portal-path");
                    confidence.AddEvidence(0.20, "boundary-crossing");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:admin-route");
        }
    }
}
