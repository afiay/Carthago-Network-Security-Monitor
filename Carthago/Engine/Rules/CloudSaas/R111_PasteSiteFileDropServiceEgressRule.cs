// SPDX-License-Identifier: MIT
// File: Engine/Rules/CloudSaas/R111_PasteSiteFileDropServiceEgressRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.CloudSaas
{
    public sealed class R111_PasteSiteFileDropServiceEgressRule : CloudSaasPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R111",
            Name: "Paste Site / File Drop Service Egress",
            Category: "CloudSaas",
            Description: "Detects suspicious paste-site or file-drop egress when the request shape indicates posting or uploading rather than ordinary viewing or landing-page traffic.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R111.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudSaasProfile(
            ruleId: "R111",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[]
            {
                "cloud.host", "http.uri", "flow.bytes", "matched_conditions"
            },
            positiveConditions: new[]
            {
                "The destination must be a paste-site or file-drop service.",
                "The request must include upload, post, or document-creation context, or otherwise carry meaningful outbound payload volume.",
                "Ordinary GET or landing-page traffic should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on simple page views or public paste reads.",
                "Do not alert on tiny requests that lack upload indicators.",
                "Do not alert when paste/drop host classification is absent."
            },
            minimumConfidence: 80,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+provider",
            falsePositives: new[]
            {
                "Approved secure-transfer workflows can legitimately use file-drop services.",
                "Developers or analysts may interact with public paste services for troubleshooting or incident response."
            },
            tuningKnobs: new[] { "Mode", "MinimumPayloadBytes", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive file-drop upload sample",
                "negative paste read sample",
                "negative landing-page sample"
            });

        public R111_PasteSiteFileDropServiceEgressRule()
            : base(Rule, Profile)
        {
        }

        protected override string? InvestigationHintOverride
            => "Determine whether the request created, uploaded, or posted content to the service and whether that service is an approved transfer mechanism for the source.";

        protected override string? TuningHintOverride
            => "Tune payload thresholds and upload-path indicators, but keep GET-only reads and landing-page traffic suppressed.";

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = BestHost(record);
            if (!NetworkBatch111115Evidence.HttpUpload(context)
                || string.IsNullOrWhiteSpace(host)
                || !IsInternalAddress(record.Source)
                || !IsExternalAddress(record.Destination)
                || !IsPasteOrDropHost(host))
            {
                return NoMatch();
            }

            var bytes = TransferBytes(record);
            var minimumPayloadBytes = IntSetting(Descriptor.RuleId, "MinimumPayloadBytes", 200_000, 8_000, 50_000_000);
            var uploadHint = NetworkBatch111115Evidence.PasteUploadContext(record);
            var automation = IsLikelyAutomationProcess(record);
            if (!uploadHint && bytes < minimumPayloadBytes)
                return NoMatch();

            var matchedConditions = new List<string> { "paste_or_drop_provider", "supporting_upload_context" };
            if (uploadHint) matchedConditions.Add("upload_or_document_path");
            if (automation) matchedConditions.Add("automation_process");
            if (bytes >= minimumPayloadBytes) matchedConditions.Add("non_trivial_payload");

            var whyMatched = $"{record.Source} sent traffic to paste or file-drop service {ProviderIdentity(host)} with upload-oriented request context.";
            var severityReason = "Severity is High because the request targeted a paste or file-drop provider with concrete posting or upload evidence rather than a simple view.";
            var falsePositives = "Approved secure-transfer or analyst workflows can use these providers. Validate whether the service is sanctioned and whether the posted content was expected.";

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule"),
                new("http.uri", "[redacted]", "http"),
                new("http.pathClassifier", uploadHint ? "upload-context" : "payload-threshold", "rule")
            };
            evidence.AddRange(AnalystContext(
                whyMatched,
                severityReason,
                falsePositives,
                "Review whether the request created or uploaded content to the service rather than reading existing content.",
                "Validate whether the provider is approved for file sharing or secure transfer in this environment.",
                "Correlate with file-access telemetry and user activity to determine what may have been posted."));

            return MatchCloud(
                context,
                SeverityLevel.High,
                $"Paste or file-drop egress observed to {ProviderIdentity(host)}",
                host,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.36, "paste-or-drop-provider");
                    if (uploadHint) confidence.AddEvidence(0.20, "upload-or-document-path");
                    if (automation) confidence.AddCorrelation(0.14, "automation-process");
                    if (bytes >= minimumPayloadBytes) confidence.AddEvidence(0.10, "non-trivial-payload");
                },
                cooldownKey: $"{record.Source}:{ProviderIdentity(host)}",
                redactHttpUri: true);
        }
    }
}
