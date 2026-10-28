// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R199_GcpMetadataCredentialRetrievalRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R199_GcpMetadataCredentialRetrievalRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R199",
            Name: "GCP Metadata Credential Retrieval",
            Category: "CloudDev",
            Description: "Detects Google metadata token or identity retrieval requests with the required metadata headers, while suppressing expected guest-agent activity.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R199.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R199",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Payload, RuleTelemetryKind.CloudAudit },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "http.path", "matched_conditions" },
            positiveConditions: new[]
            {
                "The request must target Google metadata infrastructure.",
                "The path must request service-account token or identity material.",
                "The required Metadata-Flavor header should be present."
            },
            negativeConditions: new[]
            {
                "Do not alert on generic GCP metadata reachability checks.",
                "Do not alert on expected Google guest-agent metadata access."
            },
            minimumConfidence: 88,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+host",
            falsePositives: new[] { "Expected GCE guest agents and bootstrap routines can access metadata endpoints legitimately." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive gcp metadata token request sample", "negative google guest agent sample" });

        public R199_GcpMetadataCredentialRetrievalRule() : base(Rule, Profile) { }

        private readonly NetworkBatch181185Window _window = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsGcpMetadataCredentialRequest(record)
                || !NetworkBatch196200Evidence.MetadataRequest(record, "gcp")
                || _window.Observe(record, $"{Descriptor.RuleId}:{record.Source}:{record.Destination}",
                    record.HttpUri ?? "", context.TimestampUtc, TimeSpan.FromMinutes(15), distinct: false) == 0)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "gcp_metadata_target,service_account_path,metadata_flavor_header", "rule")
            };
            evidence.AddRange(AnalystContext(
                "A typed HTTP request targeted a GCP service-account token or identity endpoint; response content and credential issuance were not observed.",
                "Severity is Critical because metadata token retrieval can expose cloud identity credentials and enable lateral cloud actions.",
                "Expected GCE agents and initialization workflows can query metadata. Validate the process lineage and intended workload behavior before escalating.",
                "Review the process lineage and any follow-on Google API calls.",
                "Confirm whether the requested service account identity is expected for the workload."));

            return MatchHttpApi(
                context,
                SeverityLevel.Critical,
                "GCP metadata credential retrieval observed",
                "GcpMetadataCredentials",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "gcp-metadata-target");
                    confidence.AddEvidence(0.26, "service-account-path");
                    confidence.AddEvidence(0.12, "metadata-flavor-header");
                },
                cooldownKey: $"{record.Source}:{record.Destination}");
        }
    }
}
