// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R133_BasicAuthenticationOverCleartextRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R133_BasicAuthenticationOverCleartextRule : IdentityAccessPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R133",
            Name: "Basic Authentication Over Cleartext",
            Category: "IdentityAccess",
            Description: "Detects actual Basic Authorization headers sent over cleartext HTTP, rather than any mention of basic auth.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R133.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIdentityAccessProfile(
            ruleId: "R133",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "matched_conditions", "http.path" },
            positiveConditions: new[]
            {
                "The request must be cleartext HTTP.",
                "An actual Authorization Basic header must be present.",
                "Documentation or discussion of basic authentication should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on HTTPS or TLS-protected requests.",
                "Do not alert on text that merely mentions basic auth."
            },
            minimumConfidence: 86,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Legacy devices or proxies may still send Basic over HTTP. Validate whether the flow is expected and whether TLS should be enforced."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive cleartext basic auth sample",
                "negative https basic auth sample"
            });

        public R133_BasicAuthenticationOverCleartextRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch131135Evidence.CleartextHttpRequest(record)
                || !NetworkBatch131135Evidence.AuthorizationHeader(record, "Basic"))
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "cleartext_http,basic_authorization_header", "rule"),
                new("http.path", "[http-request]", "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "A valid Basic Authorization header was observed on an attributed cleartext HTTP request.",
                "Severity is High because Base64-encoded Basic credentials are not encrypted by HTTP.",
                "Legacy devices and approved test systems can use Basic over HTTP; confirm the trust boundary.",
                "Identify the application and enforce TLS where possible.",
                "Review whether the exposed credential was reused."));

            return MatchIdentityAccess(context, SeverityLevel.High,
                "Basic Authorization header sent over cleartext HTTP", "CleartextBasicAuth",
                evidenceItems, confidence =>
                {
                    confidence.AddEvidence(0.44, "cleartext-http");
                    confidence.AddEvidence(0.30, "basic-authorization-header");
                    confidence.AddCorrelation(0.08, "credential-material-present");
                }, cooldownKey: $"{record.Source}:{BestHost(record)}:{NetworkBatch131135Evidence.Fingerprint(HttpPath(record))}");
        }

    }
}
