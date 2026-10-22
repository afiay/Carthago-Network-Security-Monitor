// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R215_AzureBlobContainerEnumerationRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R215_AzureBlobContainerEnumerationRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R215",
            Name: "Azure Blob Container Enumeration",
            Category: "CloudDev",
            Description: "Detects concrete Azure Blob container listing semantics instead of any blob.core.windows.net or comp=list text match.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R215.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R215",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.CloudAudit },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "http.path", "matched_conditions" },
            positiveConditions: new[]
            {
                "The host must be an Azure Blob endpoint.",
                "The query must explicitly enumerate a container using comp=list and restype=container."
            },
            negativeConditions: new[]
            {
                "Do not alert on ordinary blob object access.",
                "Do not alert on non-container Azure storage requests."
            },
            minimumConfidence: 74,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+host+path",
            falsePositives: new[] { "Legitimate storage inventory and backup tooling can enumerate Azure Blob containers intentionally." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive azure blob container list sample", "negative blob object read sample" });

        public R215_AzureBlobContainerEnumerationRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!IsAzureBlobEnumerationRequest(context.Record))
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("cloud.provider", "blob.core.windows.net", "cloud"),
                new("matched_conditions", "azure_blob_host,container_list_semantics", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The HTTP request explicitly enumerated an Azure Blob container rather than accessing a single blob object.",
                "Severity is Medium because storage container enumeration often reflects reconnaissance or broad data discovery activity.",
                "Storage inventory and backup tooling can legitimately enumerate containers. Validate the calling process and workload role.",
                "Review the container path and whether the source routinely inventories Azure storage.",
                "Confirm whether the source is authorized to enumerate the target container."));

            return MatchHttpApi(
                context,
                SeverityLevel.Medium,
                "Azure Blob container enumeration observed",
                "AzureBlobContainerEnumeration",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.22, "azure-blob-host");
                    confidence.AddEvidence(0.20, "container-list-semantics");
                },
                cooldownKey: $"{context.Record.Source}:{BestHost(context.Record)}:{HttpPath(context.Record)}");
        }
    }
}
