// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R200_AzureMetadataCredentialRetrievalRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R200_AzureMetadataCredentialRetrievalRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R200",
            Name: "Azure Metadata Credential Retrieval",
            Category: "CloudDev",
            Description: "Detects Azure IMDS token requests with the required metadata header and token path, while suppressing expected guest-agent activity.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R200.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R200",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Payload, RuleTelemetryKind.CloudAudit },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "http.path", "matched_conditions" },
            positiveConditions: new[]
            {
                "The request must target the Azure IMDS endpoint.",
                "The HTTP path must request the managed-identity OAuth token resource.",
                "The Metadata:true header and api-version parameter should be present."
            },
            negativeConditions: new[]
            {
                "Do not alert on non-identity Azure metadata paths.",
                "Do not alert on expected waagent or cloud-init metadata access."
            },
            minimumConfidence: 88,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+host",
            falsePositives: new[] { "Expected Azure guest agents and approved bootstrap routines can access IMDS legitimately." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive azure imds token request sample", "negative azure guest agent sample" });

        public R200_AzureMetadataCredentialRetrievalRule() : base(Rule, Profile) { }

        private readonly NetworkBatch181185Window _window = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch196200Evidence.MetadataRequest(record, "azure")
                || _window.Observe(record, $"{Descriptor.RuleId}:{record.Source}:{record.Destination}",
                    record.HttpUri ?? "", context.TimestampUtc, TimeSpan.FromMinutes(15), distinct: false) == 0)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "azure_imds_target,managed_identity_token_path,metadata_header", "rule")
            };
            evidence.AddRange(AnalystContext(
                "A typed HTTP request targeted Azure managed-identity token material; response content and credential issuance were not observed.",
                "Severity is Critical because managed-identity token retrieval can expose privileged cloud access for lateral movement or exfiltration.",
                "Expected Azure guest agents and initialization workflows can query IMDS. Validate the process lineage before escalating.",
                "Review the resource parameter and any follow-on Azure API access.",
                "Confirm whether the workload is expected to request managed-identity tokens directly."));

            return MatchHttpApi(
                context,
                SeverityLevel.Critical,
                "Azure metadata credential retrieval observed",
                "AzureMetadataCredentials",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "azure-imds-target");
                    confidence.AddEvidence(0.26, "managed-identity-token-path");
                    confidence.AddEvidence(0.12, "metadata-header");
                },
                cooldownKey: $"{record.Source}:{record.Destination}");
        }
    }
}
