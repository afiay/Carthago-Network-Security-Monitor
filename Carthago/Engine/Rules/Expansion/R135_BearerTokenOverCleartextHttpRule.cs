// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R135_BearerTokenOverCleartextHttpRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R135_BearerTokenOverCleartextHttpRule : IdentityAccessPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R135",
            Name: "Bearer Token Over Cleartext HTTP",
            Category: "IdentityAccess",
            Description: "Detects actual Bearer Authorization headers sent over cleartext HTTP.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R135.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIdentityAccessProfile(
            ruleId: "R135",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "matched_conditions", "http.path" },
            positiveConditions: new[]
            {
                "The request must be cleartext HTTP.",
                "An actual Authorization Bearer header must be present.",
                "Mentions of bearer tokens without a header should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on HTTPS or TLS-protected requests.",
                "Do not alert on documentation or text that merely mentions bearer auth."
            },
            minimumConfidence: 88,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Some internal test systems may still emit bearer headers over HTTP. Validate whether the token is expected and whether TLS should be enforced."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive cleartext bearer token sample",
                "negative https bearer token sample"
            });

        public R135_BearerTokenOverCleartextHttpRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsCleartextHttp(record) || !TryGetBearerAuthorization(record, out var token))
                return NoMatch();

            var path = HttpPath(record);
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "cleartext_http,bearer_authorization_header", "rule"),
                new("http.path", string.IsNullOrWhiteSpace(path) ? "/" : path, "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "A Bearer Authorization header was observed on cleartext HTTP.",
                "Severity is High because bearer tokens usually confer direct API or session access and are exposed without TLS.",
                "Legacy or internal test systems can match. Validate whether the destination is expected to accept bearer headers over HTTP.",
                "Determine whether the same bearer token remains valid and where else it was used.",
                "Review upstream proxies, logs, and network captures for wider token exposure."));

            return MatchIdentityAccess(
                context,
                SeverityLevel.High,
                "Bearer Authorization header sent over cleartext HTTP",
                "CleartextBearerToken",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.44, "cleartext-http");
                    confidence.AddEvidence(0.32, "bearer-authorization-header");
                    if (!string.IsNullOrWhiteSpace(token)) confidence.AddCorrelation(0.08, "token-material-present");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{path}");
        }
    }
}
