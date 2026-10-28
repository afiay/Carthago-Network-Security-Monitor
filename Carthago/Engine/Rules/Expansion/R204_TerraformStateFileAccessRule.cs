// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R204_TerraformStateFileAccessRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R204_TerraformStateFileAccessRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R204",
            Name: "Terraform State File Access",
            Category: "CloudDev",
            Description: "Detects direct access to Terraform state artifacts instead of matching any mention of tfstate or backend configuration text.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R204.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R204",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Payload, RuleTelemetryKind.DevOpsAudit },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "http.path", "matched_conditions" },
            positiveConditions: new[]
            {
                "The path must directly reference a Terraform state artifact such as terraform.tfstate.",
                "The host should be external or cloud-storage-like rather than an unrelated documentation path."
            },
            negativeConditions: new[]
            {
                "Do not alert on AnyText-only mentions of tfstate.",
                "Do not alert on generic Terraform documentation pages."
            },
            minimumConfidence: 82,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+host",
            falsePositives: new[] { "Approved infrastructure automation or backup systems can legitimately fetch or store Terraform state files." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive terraform state access sample", "negative terraform docs sample" });

        public R204_TerraformStateFileAccessRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch201205Evidence.TerraformState(record, out var statePath))
                return NoMatch();

            var host = BestHost(record);
            if (string.IsNullOrWhiteSpace(host) || (!IsExternalAddress(host) && !IsCloudStorageHost(host)))
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "terraform_state_path,external_or_cloud_storage_host", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The HTTP request directly referenced a Terraform state artifact on an external or cloud-storage-like host.",
                "Severity is High because Terraform state often contains cloud resource identifiers, secrets, and infrastructure topology.",
                "Approved backup, automation, or remote-state workflows can legitimately access Terraform state. Validate the workflow owner before escalating.",
                "Review the calling process and whether the state file contains credentials or cloud keys.",
                "Confirm whether the remote-state host is approved for Terraform state storage."));

            return MatchHttpApi(
                context,
                SeverityLevel.High,
                "Terraform state artifact request observed",
                "TerraformStateAccess",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "terraform-state-path");
                    confidence.AddEvidence(0.18, "external-or-cloud-storage-host");
                },
                cooldownKey: $"{record.Source}:{NetworkBatch166170Evidence.Key(host)}:{NetworkBatch166170Evidence.Key(statePath)}");
        }
    }
}
