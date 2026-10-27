// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R136_SessionCookieOverCleartextHttpRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R136_SessionCookieOverCleartextHttpRule : IdentityAccessPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R136",
            Name: "Session Cookie Over Cleartext HTTP",
            Category: "IdentityAccess",
            Description: "Detects recognizable session cookies sent over cleartext HTTP with opaque cookie values.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R136.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIdentityAccessProfile(
            ruleId: "R136",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "matched_conditions", "session.cookieName", "http.path" },
            positiveConditions: new[]
            {
                "The request must be cleartext HTTP.",
                "A recognizable session cookie must be present.",
                "The session cookie value must look opaque enough to represent real session state."
            },
            negativeConditions: new[]
            {
                "Do not alert on HTTPS or TLS-protected requests.",
                "Do not alert on analytics or cosmetic cookies."
            },
            minimumConfidence: 82,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Legacy webapps may still expose session cookies over HTTP. Validate whether TLS termination or secure-cookie controls are missing."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive cleartext session cookie sample",
                "negative analytics cookie sample"
            });

        public R136_SessionCookieOverCleartextHttpRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch136140Evidence.SessionCookie(record, out var cookieName))
                return NoMatch();

            var path = HttpPath(record);
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "cleartext_http,session_cookie", "rule"),
                new("session.cookieName", cookieName, "http"),
                new("http.path", "[http-request]", "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "A recognizable session cookie was observed on cleartext HTTP.",
                "Severity is Medium because session cookies over HTTP can enable session theft even without direct credentials.",
                "Legacy internal apps may still transmit session cookies over HTTP. Validate whether secure-cookie and TLS controls are missing.",
                "Identify whether the application is expected to run only over HTTPS.",
                "Review whether the same session cookie could be replayed from another source."));

            return MatchIdentityAccess(
                context,
                SeverityLevel.Medium,
                "Session cookie sent over cleartext HTTP",
                "CleartextSessionCookie",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.38, "cleartext-http");
                    confidence.AddEvidence(0.24, "session-cookie-name");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{NetworkBatch131135Evidence.Fingerprint(path)}:{cookieName}");
        }
    }
}
