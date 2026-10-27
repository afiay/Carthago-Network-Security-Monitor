// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R123_SuspiciousVpnLoginPathRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R123_SuspiciousVpnLoginPathRule : IdentityAccessPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R123",
            Name: "Suspicious VPN Login Path",
            Category: "IdentityAccess",
            Description: "Detects internal clients reaching external VPN portal login paths with explicit VPN appliance and SSO/login context, rather than any generic login page.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R123.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIdentityAccessProfile(
            ruleId: "R123",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Identity, RuleTelemetryKind.Authentication },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "identity_context" },
            evidenceFields: new[] { "matched_conditions", "http.path" },
            positiveConditions: new[]
            {
                "The source must be internal and the destination must be external.",
                "The HTTP path or host must indicate a VPN appliance or VPN portal login flow.",
                "Generic login pages without VPN context should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on ordinary IdP or SaaS login pages with no VPN portal indicators.",
                "Do not alert from AnyText-only matches without HTTP path and external destination context."
            },
            minimumConfidence: 72,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Legitimate remote-access portals can look similar; validate whether the destination is an approved VPN appliance or third-party access portal."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive external vpn portal login sample",
                "negative generic cloud login page sample"
            });

        public R123_SuspiciousVpnLoginPathRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasHttpContext(record) || !IsInternalAddress(record.Source) || !IsExternalAddress(BestHost(record)))
                return NoMatch();

            if (!NetworkBatch121125Evidence.VpnPortal(record, HttpPath(record)) || !HasVpnLoginPath(record))
                return NoMatch();

            var ssoContext = ContainsAny(Text(record), "saml", "oauth", "oidc", "idp");
            var matchedConditions = new List<string> { "external_destination", "vpn_portal_login_path" };
            if (ssoContext) matchedConditions.Add("sso_context");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule"),
                new("http.path", "[vpn-login-route]", "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "An internal client reached an external VPN login path with explicit VPN portal indicators.",
                "Severity is High because this can indicate access to a public VPN portal, phishing against remote-access workflows, or suspicious use of third-party VPN access paths.",
                "Approved remote-access portals, contractors, or sanctioned VPN services can match. Validate the destination against approved VPN infrastructure before escalating.",
                "Confirm whether the destination host belongs to an approved VPN or remote-access provider.",
                "Review the client process, user, and surrounding authentication events for unusual MFA, SAML, or OAuth activity."));

            return MatchIdentityAccess(
                context,
                SeverityLevel.High,
                "External VPN login path reached",
                "VpnLoginPath",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "http-context");
                    confidence.AddEvidence(0.24, "external-destination");
                    confidence.AddEvidence(0.22, "vpn-portal-login-path");
                    if (ssoContext) confidence.AddCorrelation(0.12, "sso-context");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}");
        }
    }
}
