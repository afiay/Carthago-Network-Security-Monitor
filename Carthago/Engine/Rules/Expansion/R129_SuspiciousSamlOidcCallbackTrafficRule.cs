// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R129_SuspiciousSamlOidcCallbackTrafficRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R129_SuspiciousSamlOidcCallbackTrafficRule : IdentityAccessPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R129",
            Name: "Suspicious SAML OIDC Callback Traffic",
            Category: "IdentityAccess",
            Description: "Detects SAML or OIDC callback traffic only when the callback carries suspicious token leakage or insecure redirect patterns.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R129.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIdentityAccessProfile(
            ruleId: "R129",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Identity, RuleTelemetryKind.Authentication },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "identity_context" },
            evidenceFields: new[] { "matched_conditions", "http.path" },
            positiveConditions: new[]
            {
                "The request must hit a SAML or OIDC callback-like endpoint.",
                "The callback must expose SAMLResponse, id_token, access_token, or insecure redirect parameters.",
                "Ordinary authorization-code callbacks should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on normal OIDC code and state redirects without token leakage.",
                "Do not alert on generic SSO or login pages that are not callbacks."
            },
            minimumConfidence: 68,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host+path",
            falsePositives: new[]
            {
                "Federation troubleshooting or verbose debug logging can surface callback parameters. Validate whether the flow is expected and whether the token material was exposed in a risky way."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive suspicious callback sample",
                "negative ordinary oidc code callback sample"
            });

        public R129_SuspiciousSamlOidcCallbackTrafficRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch126130Evidence.SuspiciousCallback(record, out var insecureRedirect))
                return NoMatch();

            var path = HttpPath(record);
            var matchedConditions = new List<string> { "saml_oidc_callback", "token_or_redirect_leakage" };
            if (insecureRedirect)
                matchedConditions.Add("insecure_redirect");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule"),
                new("http.path", "[sso-callback]", "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "A SAML or OIDC callback carried token-like parameters or insecure redirect material in the request URI.",
                "Severity is Medium because exposed callback parameters can leak identity assertions or session-establishing artifacts.",
                "Debug traces, federation troubleshooting, or intentionally verbose auth gateways can match. Validate whether the callback leaked material beyond the intended trust boundary.",
                "Review the callback URI, redirect target, and whether tokens or assertions were exposed in query or fragment parameters.",
                "Inspect surrounding IdP, MFA, and application login events for the same user and client."));

            return MatchIdentityAccess(
                context,
                SeverityLevel.Medium,
                "Suspicious SAML/OIDC callback leakage observed",
                "SamlOidcCallback",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "callback-path");
                    confidence.AddEvidence(0.24, "token-leakage");
                    if (insecureRedirect)
                        confidence.AddCorrelation(0.12, "insecure-redirect");
                },
                cooldownKey: $"{BestHost(record)}:sso-callback");
        }
    }
}
