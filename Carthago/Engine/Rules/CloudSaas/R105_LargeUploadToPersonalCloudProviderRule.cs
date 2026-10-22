// SPDX-License-Identifier: MIT
// File: Engine/Rules/CloudSaas/R105_LargeUploadToPersonalCloudProviderRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.CloudSaas
{
    public sealed class R105_LargeUploadToPersonalCloudProviderRule : CloudSaasPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R105",
            Name: "Large Upload to Personal Cloud Provider",
            Category: "CloudSaas",
            Description: "Detects large or sustained outbound uploads to personal or unmanaged cloud storage providers, with stronger thresholds for enterprise-sync style hosts.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R105.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudSaasProfile(
            ruleId: "R105",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_upload_or_large_flow", "saas_or_cloud_host" },
            evidenceFields: new[]
            {
                "cloud.host", "cloud.providerRoot", "flow.bytes", "cloud.totalUploadBytes", "window_seconds", "matched_conditions"
            },
            positiveConditions: new[]
            {
                "The source must upload to a recognized cloud-storage destination.",
                "The request must represent large single-event volume or sustained outbound volume within a short window.",
                "Enterprise-sync providers should require stronger evidence than consumer-oriented providers."
            },
            negativeConditions: new[]
            {
                "Do not alert on small browser uploads.",
                "Do not alert on downloads without upload context.",
                "Do not alert on enterprise sync destinations unless the volume or automation context is materially stronger."
            },
            minimumConfidence: 78,
            threshold: 2,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+provider",
            falsePositives: new[]
            {
                "Planned cloud backup, sync, and migration jobs can legitimately generate sustained upload volume.",
                "Enterprise collaboration suites may produce large uploads during normal business workflows."
            },
            tuningKnobs: new[] { "Mode", "SingleUploadBytes", "WindowUploadBytes", "EnterpriseSingleUploadBytes", "EnterpriseWindowUploadBytes" },
            requiredTests: new[]
            {
                "positive large personal-cloud upload sample",
                "negative small enterprise-sync upload sample",
                "negative missing upload-context sample"
            });

        public R105_LargeUploadToPersonalCloudProviderRule()
            : base(Rule, Profile)
        {
        }

        protected override string? InvestigationHintOverride
            => "Review whether the provider is sanctioned, whether the process is an approved sync client, and whether the upload volume aligns with the user or host role.";

        protected override string? TuningHintOverride
            => "Tune separate thresholds for consumer-oriented providers versus enterprise-sync destinations instead of globally raising the volume floor.";

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = BestHost(record);
            if (string.IsNullOrWhiteSpace(host)
                || !IsInternalAddress(record.Source)
                || !IsExternalAddress(record.Destination)
                || !IsCloudStorageHost(host))
            {
                return NoMatch();
            }

            var bytes = TransferBytes(record);
            if (bytes <= 0 || !HasUploadShape(record, 300_000))
                return NoMatch();

            var provider = ProviderIdentity(host);
            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 600, 60, 3600));
            var singleUploadBytes = IntSetting(Descriptor.RuleId, "SingleUploadBytes", 2_500_000, 250_000, 200_000_000);
            var windowUploadBytes = IntSetting(Descriptor.RuleId, "WindowUploadBytes", 6_000_000, 500_000, 500_000_000);
            var enterpriseSingleUploadBytes = IntSetting(Descriptor.RuleId, "EnterpriseSingleUploadBytes", 5_000_000, 500_000, 500_000_000);
            var enterpriseWindowUploadBytes = IntSetting(Descriptor.RuleId, "EnterpriseWindowUploadBytes", 15_000_000, 1_000_000, 1_000_000_000);
            var totalUploadBytes = AddBytesWindow($"{Descriptor.RuleId}:{record.Source}:{provider}:out", context.TimestampUtc, bytes, window);
            var automation = IsLikelyAutomationProcess(record);
            var personalCloud = IsPersonalCloudHost(host);
            var enterpriseHost = IsEnterpriseSyncHost(host);
            var strongThresholdMet = personalCloud
                ? bytes >= singleUploadBytes || totalUploadBytes >= windowUploadBytes
                : bytes >= enterpriseSingleUploadBytes || totalUploadBytes >= enterpriseWindowUploadBytes;

            if (!strongThresholdMet)
                return NoMatch();

            if (enterpriseHost && !automation && !HasUploadMetadata(record) && !personalCloud)
                return NoMatch();

            var matchedConditions = new List<string> { "large_cloud_upload", "windowed_upload_volume" };
            if (personalCloud) matchedConditions.Add("personal_or_unmanaged_provider");
            if (enterpriseHost) matchedConditions.Add("enterprise_sync_threshold");
            if (automation) matchedConditions.Add("automation_process");
            if (bytes >= (personalCloud ? singleUploadBytes : enterpriseSingleUploadBytes)) matchedConditions.Add("single_event_threshold");

            var whyMatched = $"{record.Source} sent {bytes} bytes to {provider}; the provider window now totals {totalUploadBytes} bytes within {window.TotalMinutes:F0} minutes.";
            var severityReason = "Severity is High because the rule matched concrete upload context plus large outbound volume to cloud storage, not just a provider hostname.";
            var falsePositives = "Large approved sync, migration, and backup workflows can trigger this rule. Validate whether the provider and process are part of sanctioned data-movement tooling.";

            var evidence = new List<DetectionEvidenceItem>
            {
                new("cloud.totalUploadBytes", totalUploadBytes.ToString(System.Globalization.CultureInfo.InvariantCulture), "cloud"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                whyMatched,
                severityReason,
                falsePositives,
                "Confirm whether the destination provider is approved for this source or user.",
                "Review the upload path, process lineage, and authentication context around the transfer.",
                "Tune enterprise-sync thresholds separately from consumer cloud providers to avoid hiding higher-risk unmanaged uploads."));

            return MatchCloud(
                context,
                SeverityLevel.High,
                $"Large cloud upload observed to {provider}",
                host,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.28, "large-outbound-transfer");
                    confidence.AddEvidence(0.20, "windowed-upload-volume");
                    if (personalCloud) confidence.AddCorrelation(0.12, "consumer-cloud-provider");
                    if (automation) confidence.AddCorrelation(0.10, "automation-process");
                    if (HasUploadMetadata(record)) confidence.AddEvidence(0.08, "upload-metadata");
                },
                count: totalUploadBytes >= windowUploadBytes ? 2 : 1,
                window: window,
                cooldownKey: $"{record.Source}:{provider}");
        }
    }
}
