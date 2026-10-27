// SPDX-License-Identifier: MIT
// File: Engine/Rules/CloudSaas/R104_FirstTimeCloudStorageUploadRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.CloudSaas
{
    public sealed class R104_FirstTimeCloudStorageUploadRule : CloudSaasPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R104",
            Name: "First-Time Cloud Storage Upload",
            Category: "CloudSaas",
            Description: "Detects a first-seen upload from an internal source to a cloud storage provider when the request includes clear upload context, provider classification, and baseline evidence.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R104.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudSaasProfile(
            ruleId: "R104",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Baseline },
            requiredFields: new[] { "source", "destination_or_host", "http_upload_or_large_flow", "saas_or_cloud_host" },
            evidenceFields: new[]
            {
                "cloud.host", "cloud.providerRoot", "http.method", "flow.bytes", "baseline.reason", "matched_conditions"
            },
            positiveConditions: new[]
            {
                "The source must upload to a recognized cloud storage provider.",
                "The provider must be first-seen for the source or source-process baseline.",
                "The request must carry explicit upload context, automation context, or non-trivial payload volume."
            },
            negativeConditions: new[]
            {
                "Do not alert on downloads or generic browser browsing.",
                "Do not alert when cloud-host classification is absent.",
                "Do not alert on already-known provider usage for the same source/process."
            },
            minimumConfidence: 72,
            threshold: 1,
            window: TimeSpan.FromDays(30),
            cooldown: TimeSpan.FromHours(12),
            distinctBy: "source+provider",
            falsePositives: new[]
            {
                "Newly onboarded backup or sync clients can produce first-seen uploads.",
                "Approved enterprise collaboration uploads may be expected during rollout or migration windows."
            },
            tuningKnobs: new[] { "Mode", "MinimumUploadBytes", "EnterpriseUploadBytes", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive first-seen cloud upload sample",
                "negative repeat-to-same-provider sample",
                "negative browser-only cloud browse sample"
            });

        public R104_FirstTimeCloudStorageUploadRule()
            : base(Rule, Profile)
        {
        }

        protected override string? InvestigationHintOverride
            => "Confirm whether the source or process has previously used this provider, review the upload path and payload size, and determine whether the actor is a sanctioned sync client.";

        protected override string? TuningHintOverride
            => "Tune minimum upload bytes and enterprise-provider thresholds before broad allowlisting. Keep first-seen baseline evidence as a required condition.";

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch101105Evidence.CloudUpload(context))
                return NoMatch();
            var host = BestHost(record);
            if (string.IsNullOrWhiteSpace(host)
                || !IsInternalAddress(record.Source)
                || !IsExternalAddress(record.Destination)
                || !IsCloudStorageHost(host)
                || !IsUploadMethod(record))
            {
                return NoMatch();
            }

            var bytes = TransferBytes(record);
            var minimumUploadBytes = IntSetting(Descriptor.RuleId, "MinimumUploadBytes", 250_000, 32_000, 50_000_000);
            var enterpriseUploadBytes = IntSetting(Descriptor.RuleId, "EnterpriseUploadBytes", 1_000_000, 128_000, 100_000_000);
            var automation = IsLikelyAutomationProcess(record);
            var explicitUploadMetadata = NetworkBatch101105Evidence.UploadMetadata(record);
            if (!automation && !explicitUploadMetadata && bytes < minimumUploadBytes)
                return NoMatch();

            if (IsEnterpriseSyncHost(host) && !automation && !explicitUploadMetadata && bytes < enterpriseUploadBytes)
                return NoMatch();

            var provider = ProviderIdentity(host);
            var baselineSubject = $"{record.Source}:{record.ProcessName ?? "unknown-process"}";
            var baseline = ObserveBaseline("cloud_upload_provider", baselineSubject, provider, context, $"host={host}; method={record.HttpMethod}; bytes={bytes}");
            // In-memory fallback cannot prove that a provider is genuinely
            // first-seen across process restarts or storage failures.
            if (string.Equals(baseline.Reason, "baseline unavailable", StringComparison.OrdinalIgnoreCase)
                || !baseline.IsFirstSeen)
                return NoMatch();

            var severity = automation || bytes >= enterpriseUploadBytes * 2L ? SeverityLevel.High : SeverityLevel.Medium;
            var matchedConditions = new List<string> { "first_seen_provider", "cloud_storage_upload", "explicit_upload_method" };
            if (automation) matchedConditions.Add("automation_process");
            if (explicitUploadMetadata) matchedConditions.Add("upload_metadata");
            if (bytes >= minimumUploadBytes) matchedConditions.Add("non_trivial_payload");

            var whyMatched = $"{record.Source} uploaded to first-seen provider {provider} using {record.HttpMethod} with {bytes} bytes of request volume.";
            var severityReason = severity == SeverityLevel.High
                ? "Severity is High because the first-seen provider upload also includes automation or unusually large payload volume."
                : "Severity is Medium because the activity is first-seen and has concrete upload context, but not yet the strongest automation or volume indicators.";
            var falsePositives = "New sync-client rollout or approved collaboration migrations can trigger this rule. Validate whether the provider and process are sanctioned for this host.";

            var evidence = new List<DetectionEvidenceItem>
            {
                new("baseline.reason", baseline.Reason, "baseline"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                whyMatched,
                severityReason,
                falsePositives,
                "Validate whether the source or process is approved to upload to this provider.",
                "Review the process owner, upload path, and surrounding authentication events.",
                "Allowlist known migration or backup workflows only after confirming the provider is expected."));

            return MatchCloud(
                context,
                severity,
                $"First-seen cloud storage upload observed for {provider}",
                host,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.22, "first-seen-provider");
                    if (baseline.IsFirstSeen) confidence.AddBaseline(0.16, "first-seen-baseline");
                    confidence.AddEvidence(0.18, "explicit-upload-method");
                    if (bytes >= minimumUploadBytes) confidence.AddEvidence(0.10, "non-trivial-payload");
                    if (explicitUploadMetadata) confidence.AddEvidence(0.10, "upload-metadata");
                    if (automation) confidence.AddCorrelation(0.14, "automation-process");
                    if (IsPersonalCloudHost(host)) confidence.AddCorrelation(0.08, "consumer-cloud-provider");
                },
                cooldownKey: $"{record.Source}:{provider}",
                redactHttpUri: true);
        }
    }
}
