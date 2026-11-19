// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R531_DetectionJournalDiskSpaceLowRule.cs
using System;
using System.Collections.Generic;
using System.Globalization;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R531_DetectionJournalDiskSpaceLowRule : PlatformHealthAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R531", "Detection Journal Disk Space Low", "PlatformHealthAdvanced",
            "Detects explicit low-disk/low-free-space telemetry for the detection journal path.", SeverityLevel.Critical, "Rules.R531.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreatePlatformHealthProfile("R531", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert,
            new[] { RuleTelemetryKind.Flow }, new[] { "platform_health_event", "detection_journal", "disk_space_signal" },
            new[] { "journal.path", "matched_conditions" },
            new[] { "A confirmed OS capacity sample must be bound to the configured DetectionJournal path.", "Both configured byte and percentage thresholds must be breached after two distinct samples." },
            new[] { "Packet text, journal write exceptions, unrelated volumes and maintenance samples are not low-space evidence." },
            90, 1, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(20), "journal-path",
            new[] { "Small lab disks can trigger this during replay testing; production sensors should still alert." },
            new[] { "Mode", "CooldownSeconds", "MinimumFreeDiskPercent", "MinimumFreeDiskBytes" },
            new[] { "positive detection journal disk low", "negative unrelated disk log" });
        public R531_DetectionJournalDiskSpaceLowRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var evidence = context.Record.TrustedJournalCapacityEvidence;
            if (evidence is null)
            {
                var missing = PlatformHealthProducerEvidenceBoundary.GetMissingProducer(Descriptor.RuleId);
                return RuleEvaluationResult.NoMatch(
                    Descriptor.RuleId,
                    RuleNoMatchReasonCategory.InsufficientEvidence,
                    missing?.Code ?? "JOURNAL_FREE_SPACE_TRUSTED_VOLUME_METRIC_UNAVAILABLE",
                    missing?.Detail ?? "A typed OS capacity observation from the configured DetectionJournal owner is required.");
            }

            if (!evidence.IsValid)
                return RuleEvaluationResult.NoMatch(
                    Descriptor.RuleId,
                    RuleNoMatchReasonCategory.InsufficientEvidence,
                    "JOURNAL_CAPACITY_EVIDENCE_INVALID",
                    "The journal capacity observation failed its immutable owner, timestamp, bounds or dual-threshold checks.");

            var journal = "sha256:" + evidence.JournalIdentity;
            var items = new List<DetectionEvidenceItem>
            {
                new("journal.path", journal, "configured-journal-owner"),
                new("journal.availableBytes", evidence.AvailableBytes.ToString(CultureInfo.InvariantCulture), "os-volume-capacity"),
                new("journal.totalBytes", evidence.TotalBytes.ToString(CultureInfo.InvariantCulture), "os-volume-capacity"),
                new("journal.minimumFreeBytes", evidence.MinimumFreeBytes.ToString(CultureInfo.InvariantCulture), "configured-policy"),
                new("journal.minimumFreePercent", evidence.MinimumFreePercent.ToString("R", CultureInfo.InvariantCulture), "configured-policy"),
                new("journal.sampledAtUtc", evidence.SampledAtUtc.ToString("O", CultureInfo.InvariantCulture), "os-volume-capacity"),
                new("matched_conditions", "trusted_os_volume_capacity,two_sample_confirmation,below_byte_and_percent_thresholds", "rule")
            };
            items.AddRange(AnalystContext(
                "The configured DetectionJournal volume remained below both operator-configured free-space thresholds across two distinct samples.",
                "Critical because journal capacity exhaustion can prevent durable recording of detections.",
                "Unrelated volumes, packet text, failed writes and maintenance intervals are excluded.",
                "Free space on the configured journal volume or move the journal using an approved configuration change.",
                "Verify the journal's durable write path after remediation."));

            return MatchPlatformHealth(
                context,
                SeverityLevel.Critical,
                "Detection journal disk space low",
                "DetectionJournalDiskSpaceLow",
                items,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "platform-health-anchor");
                    confidence.AddEvidence(0.30, "configured-journal-identity");
                    confidence.AddEvidence(0.26, "confirmed-dual-threshold-os-capacity");
                },
                cooldownKey: journal);
        }
    }
}
