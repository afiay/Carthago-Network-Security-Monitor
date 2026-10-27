// SPDX-License-Identifier: MIT
// File: Engine/Rules/CloudSaas/R107_ExfiltrationSplitAcrossManyDestinationsRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.CloudSaas
{
    public sealed class R107_ExfiltrationSplitAcrossManyDestinationsRule : CloudSaasPrecisionDetectionRuleBase
    {
        private readonly NetworkBatch081085Dedup _seen = new();
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R107",
            Name: "Exfiltration Split Across Many Destinations",
            Category: "CloudSaas",
            Description: "Detects suspicious outbound transfer volume deliberately spread across multiple external destinations, while suppressing ordinary browsing fan-out.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R107.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudSaasProfile(
            ruleId: "R107",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http },
            requiredFields: new[] { "source", "destination_or_host", "http_upload_or_large_flow" },
            evidenceFields: new[]
            {
                "flow.bytes", "cloud.totalUploadBytes", "cloud.distinctDestinations", "count", "window_seconds", "matched_conditions"
            },
            positiveConditions: new[]
            {
                "The source must push non-trivial outbound volume to multiple external destinations in a short window.",
                "Each counted event must carry upload-like or otherwise suspicious transfer context.",
                "Ordinary web browsing fan-out should not satisfy the per-event or volume thresholds."
            },
            negativeConditions: new[]
            {
                "Do not alert on low-volume browsing across many sites.",
                "Do not alert on a single upload destination.",
                "Do not alert when transfer events lack upload-like context."
            },
            minimumConfidence: 78,
            threshold: 6,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Parallel backup or mirroring workflows can distribute data across many destinations.",
                "Security tooling or content delivery workflows may contact many remote endpoints with higher-than-usual volume."
            },
            tuningKnobs: new[] { "Mode", "DestinationThreshold", "WindowUploadBytes", "MinimumEventBytes", "MinimumTransferEvents" },
            requiredTests: new[]
            {
                "positive split-exfil sample",
                "negative low-volume browsing fan-out sample",
                "negative single-destination upload sample"
            });

        public R107_ExfiltrationSplitAcrossManyDestinationsRule()
            : base(Rule, Profile)
        {
        }

        protected override string? InvestigationHintOverride
            => "Compare the destination set, total outbound volume, and per-event upload context to determine whether the host is spreading transfers intentionally to dilute simple volume controls.";

        protected override string? TuningHintOverride
            => "Tune the minimum per-event bytes and suspicious-event count before raising destination thresholds. Keep ordinary browsing suppression intact.";

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch101105Evidence.CloudUpload(context) || !_seen.First(record.Id, context.TimestampUtc))
                return NoMatch();
            if (!IsInternalAddress(record.Source) || !IsExternalAddress(record.Destination))
                return NoMatch();

            var bytes = TransferBytes(record);
            var minimumEventBytes = IntSetting(Descriptor.RuleId, "MinimumEventBytes", 250_000, 16_000, 100_000_000);
            if (bytes < minimumEventBytes)
                return NoMatch();

            var host = BestHost(record);
            var suspiciousTransfer = IsUploadMethod(record)
                                     || NetworkBatch101105Evidence.UploadMetadata(record)
                                     || (!string.IsNullOrWhiteSpace(host) && (IsCloudStorageHost(host) || IsPasteOrDropHost(host) || IsChatApiHost(host)))
                                     || (!IsLikelyBrowserProcess(record.ProcessName) && bytes >= minimumEventBytes * 2L);
            if (!suspiciousTransfer)
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 600, 60, 3600));
            var destinationThreshold = IntSetting(Descriptor.RuleId, "DestinationThreshold", 6, 3, 128);
            var windowUploadBytes = IntSetting(Descriptor.RuleId, "WindowUploadBytes", 6_000_000, 500_000, 1_000_000_000);
            var minimumTransferEvents = IntSetting(Descriptor.RuleId, "MinimumTransferEvents", 4, 2, 128);
            var destinationIdentity = !string.IsNullOrWhiteSpace(host) ? $"{ProviderIdentity(host)}|{record.Destination}" : record.Destination ?? "unknown";
            var distinctDestinations = CountDistinctValues($"{Descriptor.RuleId}:{record.Source}:destinations", destinationIdentity, context.TimestampUtc, window);
            var transferEvents = CountWindowEvents($"{Descriptor.RuleId}:{record.Source}:events", context.TimestampUtc, window);
            var totalUploadBytes = AddBytesWindow($"{Descriptor.RuleId}:{record.Source}:bytes", context.TimestampUtc, bytes, window);
            if (distinctDestinations < destinationThreshold || transferEvents < minimumTransferEvents || totalUploadBytes < windowUploadBytes)
                return NoMatch();

            var matchedConditions = new List<string> { "multi_destination_outbound_volume", "suspicious_transfer_context" };
            if (!string.IsNullOrWhiteSpace(host) && IsPasteOrDropHost(host)) matchedConditions.Add("paste_or_drop_provider");
            if (!string.IsNullOrWhiteSpace(host) && IsCloudStorageHost(host)) matchedConditions.Add("cloud_provider");
            if (NetworkBatch101105Evidence.UploadMetadata(record)) matchedConditions.Add("upload_metadata");

            var whyMatched = $"{record.Source} sent {totalUploadBytes} bytes across {distinctDestinations} distinct external destinations in {window.TotalMinutes:F0} minutes with {transferEvents} suspicious transfer events.";
            var severityReason = "Severity is High because the outbound transfer volume is being distributed across many destinations with upload-like context, which is consistent with split exfiltration rather than casual browsing.";
            var falsePositives = "Distributed backup or replication tasks can resemble this pattern. Validate whether the destination set and timing align with sanctioned data-movement tooling.";

            var evidence = new List<DetectionEvidenceItem>
            {
                new("cloud.totalUploadBytes", totalUploadBytes.ToString(System.Globalization.CultureInfo.InvariantCulture), "cloud"),
                new("cloud.distinctDestinations", distinctDestinations.ToString(System.Globalization.CultureInfo.InvariantCulture), "cloud"),
                new("count", transferEvents.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                whyMatched,
                severityReason,
                falsePositives,
                "Review the full destination set and whether the same source distributed similar payload sizes across them.",
                "Determine whether the activity maps to approved replication, backup, or content distribution jobs.",
                "Correlate with authentication, endpoint, and file-access telemetry to identify what data may have been staged before transfer."));

            return MatchCloud(
                context,
                SeverityLevel.High,
                $"Outbound transfer split across {distinctDestinations} destinations from {record.Source}",
                host,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "multi-destination-transfer");
                    confidence.AddEvidence(0.20, "windowed-upload-volume");
                    confidence.AddEvidence(0.14, "suspicious-transfer-context");
                    if (!string.IsNullOrWhiteSpace(host) && IsPasteOrDropHost(host)) confidence.AddCorrelation(0.10, "paste-or-drop-destination");
                    if (NetworkBatch101105Evidence.UploadMetadata(record)) confidence.AddEvidence(0.08, "upload-metadata");
                },
                count: transferEvents,
                window: window,
                cooldownKey: $"{record.Source}");
        }
    }
}
