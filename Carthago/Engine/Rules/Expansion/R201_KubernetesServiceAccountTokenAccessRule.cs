// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R201_KubernetesServiceAccountTokenAccessRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R201_KubernetesServiceAccountTokenAccessRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R201",
            Name: "Kubernetes Service Account Token Access",
            Category: "CloudDev",
            Description: "Detects non-platform access to mounted Kubernetes service-account tokens or the TokenRequest API, while suppressing expected Kubernetes components.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R201.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R201",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Payload, RuleTelemetryKind.CloudAudit },
            requiredFields: new[] { "source", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "http.path", "matched_conditions" },
            positiveConditions: new[]
            {
                "The telemetry must reference the mounted service-account token path or the Kubernetes TokenRequest API.",
                "Known Kubernetes component processes should remain suppressed.",
                "The request should come from a user or automation process rather than platform plumbing."
            },
            negativeConditions: new[]
            {
                "Do not alert on kubelet, kubectl, or other normal platform components.",
                "Do not alert on generic Kubernetes API traffic that does not touch service-account tokens."
            },
            minimumConfidence: 86,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+host",
            falsePositives: new[] { "Approved cluster administration or bootstrap components can request service-account tokens legitimately." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive service account token access sample", "negative kubelet token access sample" });

        public R201_KubernetesServiceAccountTokenAccessRule() : base(Rule, Profile) { }

        private readonly NetworkBatch181185Window _window = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (IsLikelyKubernetesComponentProcess(record.ProcessName)
                || !NetworkBatch201205Evidence.KubernetesTokenRequest(record, out var classifier)
                || _window.Observe(record, $"{Descriptor.RuleId}:{record.Source}:{record.Destination}",
                    classifier, context.TimestampUtc, TimeSpan.FromMinutes(15), distinct: false) == 0)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", classifier, "rule")
            };
            evidence.AddRange(AnalystContext(
                "An attributed HTTP POST requested a Kubernetes service-account TokenRequest API endpoint; no token response was observed.",
                "Severity is Critical because service-account token access can expose cluster credentials and enable API abuse or lateral movement inside Kubernetes.",
                "Cluster bootstrap or administrative tooling can legitimately request tokens. Validate process lineage, namespace, and intended workload role before escalating.",
                "Review the calling process and whether it immediately accessed the Kubernetes API.",
                "Confirm whether the token target belongs to an approved controller or administration workflow."));

            return MatchHttpApi(
                context,
                SeverityLevel.Critical,
                "Kubernetes service-account token access observed",
                "KubernetesServiceAccountToken",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.28, "serviceaccount-token-access");
                    if (classifier.Contains("mounted_", StringComparison.OrdinalIgnoreCase)) confidence.AddEvidence(0.14, "mounted-token-path");
                    if (classifier.Contains("tokenrequest", StringComparison.OrdinalIgnoreCase)) confidence.AddEvidence(0.16, "tokenrequest-api");
                },
                cooldownKey: $"{record.Source}:{record.Destination}:{classifier}");
        }
    }
}
