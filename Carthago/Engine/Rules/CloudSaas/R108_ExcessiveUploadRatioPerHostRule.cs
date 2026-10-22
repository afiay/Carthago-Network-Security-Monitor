// SPDX-License-Identifier: MIT
// File: Engine/Rules/CloudSaas/R108_ExcessiveUploadRatioPerHostRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.CloudSaas
{
    public sealed class R108_ExcessiveUploadRatioPerHostRule : CloudSaasPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R108",
            Name: "Excessive Upload Ratio Per Host",
            Category: "CloudSaas",
            Description: "Measures outbound-versus-inbound byte ratio per source and provider within a bounded window, rather than accumulating unbounded volume per source.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R108.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudSaasProfile(
            ruleId: "R108",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http },
            requiredFields: new[] { "source", "destination_or_host", "saas_or_cloud_host" },
            evidenceFields: new[]
            {
                "cloud.host", "cloud.providerRoot", "cloud.outboundBytes", "cloud.inboundBytes", "cloud.uploadRatio", "window_seconds", "matched_conditions"
            },
            positiveConditions: new[]
            {
                "The rule must compare outbound and inbound bytes for the same source-provider pair within a bounded window.",
                "The destination should be a cloud, SaaS, paste, or comparable egress target.",
                "The outbound ratio or outbound-only volume must be materially high before alerting."
            },
            negativeConditions: new[]
            {
                "Do not alert from lifetime-accumulated source totals.",
                "Do not alert when inbound traffic is comparable to outbound traffic.",
                "Do not alert on low-volume single flows."
            },
            minimumConfidence: 80,
            threshold: 2,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+provider",
            falsePositives: new[]
            {
                "Approved backup and sync clients can produce sustained outbound-heavy ratios.",
                "Upload-first APIs may naturally show little inbound data compared with outbound payload size."
            },
            tuningKnobs: new[] { "Mode", "WindowSeconds", "MinimumOutboundBytes", "RatioThreshold", "OutboundOnlyBytes" },
            requiredTests: new[]
            {
                "positive high upload-ratio sample",
                "negative balanced bidirectional sample",
                "negative low-volume sample"
            });

        public R108_ExcessiveUploadRatioPerHostRule()
            : base(Rule, Profile)
        {
        }

        protected override string? InvestigationHintOverride
            => "Review the source-provider pair over the configured window, compare inbound and outbound totals, and determine whether the ratio matches expected sync or backup behavior.";

        protected override string? TuningHintOverride
            => "Tune windowed outbound bytes and ratio thresholds per provider class. Avoid reverting to source-wide lifetime counters.";

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = BestHost(record);
            var bytes = TransferBytes(record);
            if (bytes <= 0)
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 900, 60, 7200));
            var minimumOutboundBytes = IntSetting(Descriptor.RuleId, "MinimumOutboundBytes", 8_000_000, 500_000, 1_000_000_000);
            var ratioThreshold = DoubleSetting(Descriptor.RuleId, "RatioThreshold", 6.0, 1.5, 100.0);
            var outboundOnlyBytes = IntSetting(Descriptor.RuleId, "OutboundOnlyBytes", 12_000_000, 500_000, 1_000_000_000);

            if (IsExternalAddress(record.Source) && IsInternalAddress(record.Destination) && !string.IsNullOrWhiteSpace(host))
            {
                var inboundProvider = ProviderIdentity(host);
                AddBytesWindow($"{Descriptor.RuleId}:{record.Destination}:{inboundProvider}:in", context.TimestampUtc, bytes, window);
                return NoMatch();
            }

            if (!IsInternalAddress(record.Source)
                || !IsExternalAddress(record.Destination)
                || string.IsNullOrWhiteSpace(host)
                || !(IsCloudStorageHost(host) || IsPasteOrDropHost(host) || IsChatApiHost(host) || IsSaasBusinessHost(host)))
            {
                return NoMatch();
            }

            var provider = ProviderIdentity(host);
            var outboundBytes = AddBytesWindow($"{Descriptor.RuleId}:{record.Source}:{provider}:out", context.TimestampUtc, bytes, window);
            var inboundBytes = SumBytesWindow($"{Descriptor.RuleId}:{record.Source}:{provider}:in", context.TimestampUtc, window);
            var uploadRatio = inboundBytes > 0 ? outboundBytes / Math.Max(1.0, inboundBytes) : outboundBytes;
            var uploadContext = HasUploadShape(record, 250_000) || !IsLikelyBrowserProcess(record.ProcessName);
            if (!uploadContext && outboundBytes < outboundOnlyBytes)
                return NoMatch();

            var ratioMatched = inboundBytes > 0 && outboundBytes >= minimumOutboundBytes && uploadRatio >= ratioThreshold;
            var outboundOnlyMatched = inboundBytes == 0 && outboundBytes >= outboundOnlyBytes;
            if (!ratioMatched && !outboundOnlyMatched)
                return NoMatch();

            var matchedConditions = new List<string> { "windowed_provider_ratio" };
            if (ratioMatched) matchedConditions.Add("high_outbound_inbound_ratio");
            if (outboundOnlyMatched) matchedConditions.Add("high_outbound_only_volume");
            if (HasUploadMetadata(record)) matchedConditions.Add("upload_metadata");
            if (IsPasteOrDropHost(host)) matchedConditions.Add("paste_or_drop_provider");

            var whyMatched = ratioMatched
                ? $"{record.Source} sent {outboundBytes} bytes to {provider} and received {inboundBytes} bytes back within {window.TotalMinutes:F0} minutes, for an outbound ratio of {uploadRatio:F1}."
                : $"{record.Source} sent {outboundBytes} bytes to {provider} within {window.TotalMinutes:F0} minutes without any observed inbound return traffic for the same provider window.";
            var severityReason = "Severity is High because the rule measured a strong provider-scoped outbound imbalance within a bounded window, which is more specific than generic large egress.";
            var falsePositives = "Approved sync or backup workflows can produce outbound-heavy ratios. Validate whether the provider, process, and timing align with sanctioned transfer behavior.";

            var evidence = new List<DetectionEvidenceItem>
            {
                new("cloud.outboundBytes", outboundBytes.ToString(System.Globalization.CultureInfo.InvariantCulture), "cloud"),
                new("cloud.inboundBytes", inboundBytes.ToString(System.Globalization.CultureInfo.InvariantCulture), "cloud"),
                new("cloud.uploadRatio", uploadRatio.ToString("F1", System.Globalization.CultureInfo.InvariantCulture), "cloud"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                whyMatched,
                severityReason,
                falsePositives,
                "Review the provider-scoped traffic timeline to see whether uploads dominate the session window.",
                "Check whether the process and user align with sanctioned backup or sync tooling.",
                "Correlate with file-access and endpoint telemetry if the source is not expected to move large data externally."));

            return MatchCloud(
                context,
                SeverityLevel.High,
                $"Outbound-heavy provider ratio observed for {provider}",
                host,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.40, "provider-scoped-ratio");
                    if (ratioMatched) confidence.AddEvidence(0.20, "high-outbound-inbound-ratio");
                    if (outboundOnlyMatched) confidence.AddEvidence(0.20, "high-outbound-only-volume");
                    if (HasUploadMetadata(record)) confidence.AddEvidence(0.08, "upload-metadata");
                    if (IsPersonalCloudHost(host)) confidence.AddCorrelation(0.12, "consumer-cloud-provider");
                    if (IsPasteOrDropHost(host)) confidence.AddCorrelation(0.08, "paste-or-drop-provider");
                },
                window: window,
                cooldownKey: $"{record.Source}:{provider}");
        }
    }
}
