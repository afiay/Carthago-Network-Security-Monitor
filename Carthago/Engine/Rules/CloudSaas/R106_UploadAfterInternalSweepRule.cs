// SPDX-License-Identifier: MIT
// File: Engine/Rules/CloudSaas/R106_UploadAfterInternalSweepRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.CloudSaas
{
    public sealed class R106_UploadAfterInternalSweepRule : CloudSaasPrecisionDetectionRuleBase
    {
        private readonly NetworkBatch081085Dedup _seen = new();
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R106",
            Name: "Upload After Internal Sweep",
            Category: "CloudSaas",
            Description: "Detects outbound uploads that follow an internal administrative sweep from the same source, using self-contained sweep state instead of generic host-only matching.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R106.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudSaasProfile(
            ruleId: "R106",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port", "http_upload_or_large_flow" },
            evidenceFields: new[]
            {
                "cloud.host", "cloud.providerRoot", "flow.bytes", "sweep.distinctTargets", "sweep.lastObservedUtc", "matched_conditions"
            },
            positiveConditions: new[]
            {
                "The source must first exhibit a short-window internal sweep against administrative destinations or protocols.",
                "An outbound upload or large transfer must follow from the same source within the configured delay window.",
                "The upload destination should be an external cloud, SaaS, paste, or similarly relevant egress target unless the volume is especially strong."
            },
            negativeConditions: new[]
            {
                "Do not alert on internal sweep records alone.",
                "Do not alert on outbound traffic without recent sweep context.",
                "Do not alert on small external traffic bursts that lack upload context."
            },
            minimumConfidence: 82,
            threshold: 4,
            window: TimeSpan.FromMinutes(30),
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source",
            falsePositives: new[]
            {
                "Legitimate admin or vulnerability scans followed by sanctioned file distribution can look similar.",
                "Jump hosts or management servers may perform broad internal access before normal uploads."
            },
            tuningKnobs: new[] { "Mode", "SweepThreshold", "SweepWindowSeconds", "UploadDelaySeconds", "MinimumUploadBytes" },
            requiredTests: new[]
            {
                "positive upload-after-sweep sample",
                "negative insufficient-sweep sample",
                "negative sweep-only sample"
            });

        public R106_UploadAfterInternalSweepRule()
            : base(Rule, Profile)
        {
        }

        protected override string? InvestigationHintOverride
            => "Review the internal destinations contacted before the upload, identify whether they map to admin services, and determine whether the subsequent external transfer aligns with normal operator behavior.";

        protected override string? TuningHintOverride
            => "Tune the sweep threshold and upload delay window before changing egress host allowlists. This rule is strongest when the pre-upload sweep remains mandatory.";

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (NetworkBatch106110Evidence.InternalAdminProbe(context))
                TrackPotentialInternalSweep(context.Record, context.TimestampUtc);

            var record = context.Record;
            if (!NetworkBatch101105Evidence.CloudUpload(context) || !_seen.First(record.Id, context.TimestampUtc))
                return NoMatch();
            if (!IsInternalAddress(record.Source) || !IsExternalAddress(record.Destination))
                return NoMatch();

            var bytes = TransferBytes(record);
            var minimumUploadBytes = IntSetting(Descriptor.RuleId, "MinimumUploadBytes", 500_000, 64_000, 100_000_000);
            if (bytes < minimumUploadBytes && !HasUploadShape(record, minimumUploadBytes))
                return NoMatch();

            var sweepWindow = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "SweepWindowSeconds", 1_200, 60, 7_200));
            var uploadDelay = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "UploadDelaySeconds", 1_800, 60, 14_400));
            var sweepThreshold = IntSetting(Descriptor.RuleId, "SweepThreshold", 4, 2, 128);
            var sweepCount = RecentInternalSweepCount(record.Source, context.TimestampUtc, sweepWindow);
            var sweepAt = RecentInternalSweepAt(record.Source, context.TimestampUtc, uploadDelay);
            if (sweepCount < sweepThreshold || !sweepAt.HasValue)
                return NoMatch();

            var host = BestHost(record);
            var relevantEgress = !string.IsNullOrWhiteSpace(host)
                && (IsCloudStorageHost(host) || IsPasteOrDropHost(host) || IsChatApiHost(host) || IsSaasBusinessHost(host));
            if (!relevantEgress && bytes < minimumUploadBytes * 4L)
                return NoMatch();

            if (!string.IsNullOrWhiteSpace(host) && IsEnterpriseSyncHost(host) && !IsLikelyAutomationProcess(record) && bytes < minimumUploadBytes * 6L)
                return NoMatch();

            var matchedConditions = new List<string> { "recent_internal_sweep", "outbound_upload_after_sweep" };
            if (relevantEgress) matchedConditions.Add("relevant_external_egress_target");
            if (NetworkBatch101105Evidence.UploadMetadata(record)) matchedConditions.Add("upload_metadata");
            if (IsLikelyAutomationProcess(record)) matchedConditions.Add("automation_process");

            var provider = ProviderIdentity(host);
            var whyMatched = $"{record.Source} touched {sweepCount} internal targets, then uploaded {bytes} bytes to {provider} {Math.Round((context.TimestampUtc - sweepAt.Value).TotalMinutes, 1)} minutes later.";
            var severityReason = "Severity is Critical because the rule correlated lateral or administrative sweep behavior with subsequent external upload activity from the same source.";
            var falsePositives = "Management systems, scanners, or admin jump hosts can resemble this pattern. Validate the internal targets, user intent, and whether the external destination is approved.";

            var evidence = new List<DetectionEvidenceItem>
            {
                new("sweep.distinctTargets", sweepCount.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("sweep.lastObservedUtc", sweepAt.Value.ToString("O", System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                whyMatched,
                severityReason,
                falsePositives,
                "Review the pre-upload internal connections for SMB, WinRM, RDP, SSH, or similar administrative access patterns.",
                "Identify the user and process behind the outbound transfer and confirm whether the destination is sanctioned.",
                "Escalate quickly if the internal sweep touched sensitive or unusual internal targets."));

            return MatchCloud(
                context,
                SeverityLevel.Critical,
                $"Outbound upload followed recent internal sweep from {record.Source}",
                host,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "recent-internal-sweep");
                    confidence.AddEvidence(0.24, "outbound-upload-context");
                    if (relevantEgress) confidence.AddCorrelation(0.14, "relevant-external-egress");
                    if (IsLikelyAutomationProcess(record)) confidence.AddCorrelation(0.12, "automation-process");
                    if (bytes >= minimumUploadBytes * 4L) confidence.AddEvidence(0.08, "large-upload-volume");
                },
                count: sweepCount,
                window: uploadDelay,
                cooldownKey: $"{record.Source}:{provider}");
        }
    }
}
