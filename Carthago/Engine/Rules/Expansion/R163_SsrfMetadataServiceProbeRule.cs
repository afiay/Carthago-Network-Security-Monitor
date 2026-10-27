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
            Description: "Observes cloud metadata credential requests from non-standard callers; SSRF requires separate causal evidence.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R163.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R163",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Payload },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "metadata_credential_request", "process.name" },
            evidenceFields: new[] { "matched_conditions", "http.path", "process.name" },
            positiveConditions: new[]
            {
                "The HTTP destination and host must identify a cloud metadata service and the path must request credentials.",
                "Known metadata agent or cloud guest processes should remain suppressed.",
                "Missing process attribution must prevent Alert promotion even if the request is suspicious.",
                "Free-form references and metadata protocol headers alone are not indicators of credential theft."
            },
            negativeConditions: new[]
            {
                "Do not alert on ordinary guest-agent metadata retrieval.",
                "Do not alert when the destination is not a metadata service host.",
                "Do not alert on ordinary instance metadata lookups or authorized IMDSv2 token use."
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
                "negative known guest agent metadata sample",
                "negative ordinary instance metadata request sample",
                "negative forged metadata host header sample"
            });

        public R163_SsrfMetadataServiceProbeRule()
            : base(Rule, Profile)
        {
        }

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasHttpContext(record) || record.IsUdp || record.IsQuic || record.DnsQname != null || !HasMethod(record, "GET", "HEAD")
                || !SensitiveTelemetryContracts.HasCredentialBearingMetadataRequest(record)
                || SensitiveTelemetryContracts.IsKnownCloudMetadataAgent(record.ProcessName))
                return NoMatch();

            var path = HttpPath(record);
            var matchedConditions = new List<string> { "metadata_service_target", "credential_path" };
            var hasImdsV2Token = TryGetHeaderValue(record, "X-aws-ec2-metadata-token", out var imdsV2Token)
                                 && !string.IsNullOrWhiteSpace(imdsV2Token);
            if (HeaderContains(record, "Metadata", "true") || HeaderContains(record, "Metadata-Flavor", "Google"))
                matchedConditions.Add("metadata_header");
            if (hasImdsV2Token)
                matchedConditions.Add("imds_v2_token_header");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule"),
                new("http.routeCategory", "metadata_credential", "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "A non-standard HTTP caller requested a cloud metadata credential path; this alone does not prove SSRF.",
                "Potential impact is Critical if independently corroborated SSRF exposes instance credentials; direct metadata access is not sufficient proof.",
                "Legitimate bootstrap agents or cloud guest tooling may query metadata. Validate the source process carefully before escalating.",
                "Correlate inbound untrusted requests with outbound metadata access using trace or process identity, redirect chain and timing; do not infer causality from timing alone.",
                "Confirm whether the caller is an approved agent, bootstrap task or user-facing application, and verify independent causal evidence before promotion."));

            if (!_replay.Observe(record, context.TimestampUtc)) return NoMatch();

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
                    // IMDSv2 tokens and provider-required headers are normal protocol
                    // mechanics, not independent evidence of attacker-controlled SSRF.
                    // Keep them as context above but never boost detection confidence.
                },
                cooldownKey: $"{record.Source}:{record.Destination}:{path}");
        }
    }
}
