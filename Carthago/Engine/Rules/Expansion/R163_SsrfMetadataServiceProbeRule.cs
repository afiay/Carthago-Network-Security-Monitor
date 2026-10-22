// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R163_SsrfMetadataServiceProbeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R163_SsrfMetadataServiceProbeRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R163",
            Name: "SSRF Metadata Service Probe",
            Category: "HttpApi",
            Description: "Detects HTTP requests to cloud metadata credential paths from non-standard callers instead of alerting on every metadata lookup.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R163.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R163",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Payload },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "matched_conditions", "http.path", "process.name" },
            positiveConditions: new[]
            {
                "The request must target a concrete cloud metadata host and credential-bearing metadata path.",
                "Known metadata agent or cloud guest processes should remain suppressed.",
                "Free-form references to metadata hosts without real HTTP destination context should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on ordinary guest-agent metadata retrieval.",
                "Do not alert when the destination is not a metadata service host."
            },
            minimumConfidence: 84,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(15),
            distinctBy: "source+path",
            falsePositives: new[]
            {
                "Cloud guest agents, bootstrap code, and approved secret retrieval workflows can access metadata endpoints legitimately."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive metadata credential path sample",
                "negative known guest agent metadata sample"
            });

        public R163_SsrfMetadataServiceProbeRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasHttpContext(record) || !HasMethod(record, "GET", "HEAD") || !IsMetadataServiceProbe(record) || IsKnownMetadataProcess(record))
                return NoMatch();

            var path = HttpPath(record);
            var matchedConditions = new List<string> { "metadata_service_target", "credential_path" };
            if (HeaderContains(record, "Metadata", "true") || HeaderContains(record, "Metadata-Flavor", "Google"))
                matchedConditions.Add("metadata_header");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule"),
                new("http.path", string.IsNullOrWhiteSpace(path) ? "/" : path, "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "A non-standard HTTP caller reached a cloud metadata credential path.",
                "Severity is Critical because metadata credential endpoints are frequently targeted by SSRF for token and instance-profile theft.",
                "Legitimate bootstrap agents or cloud guest tooling may query metadata. Validate the source process carefully before escalating.",
                "Review the source process and recent web requests for SSRF indicators, open redirects, or server-side fetch behavior.",
                "Confirm whether the caller is an approved cloud agent or a user-facing application process."));

            return MatchHttpApi(
                context,
                SeverityLevel.Critical,
                "Cloud metadata credential path queried",
                "MetadataServiceProbe",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "metadata-service-target");
                    confidence.AddEvidence(0.28, "credential-path");
                    if (HeaderContains(record, "Metadata", "true") || HeaderContains(record, "Metadata-Flavor", "Google"))
                        confidence.AddCorrelation(0.08, "metadata-header");
                },
                cooldownKey: $"{record.Source}:{record.Destination}:{path}");
        }
    }
}
