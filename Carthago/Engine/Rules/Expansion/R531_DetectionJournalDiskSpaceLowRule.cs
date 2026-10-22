// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R531_DetectionJournalDiskSpaceLowRule.cs
using System;
using System.Collections.Generic;
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
            new[] { "The event must reference the detection journal or durable event store.", "The event must include low disk, low free space, write risk, or retention failure semantics." },
            new[] { "Do not alert on generic disk messages unrelated to the detection journal.", "Do not alert on informational retention cleanup success." },
            90, 1, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(20), "journal-path",
            new[] { "Small lab disks can trigger this during replay testing; production sensors should still alert." },
            new[] { "Mode", "CooldownSeconds", "MinimumFreeDiskPercent", "MinimumFreeDiskBytes" },
            new[] { "positive detection journal disk low", "negative unrelated disk log" });
        public R531_DetectionJournalDiskSpaceLowRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record; var text = Text(r);
            if (!IsPlatformHealthRecord(r) || !ContainsAny(text, "journal", "detection journal", "event journal", "detections-", "durable event store")) return NoMatch();
            if (!ContainsAny(text, "disk space low", "low disk", "free space", "out of space", "no space", "write risk", "retention failed")) return NoMatch();
            if (ContainsAny(text, "cleanup succeeded", "retention success")) return NoMatch();
            var journal = MetricKey(r);
            var e = new List<DetectionEvidenceItem> { new("journal.path", journal, "platform-health"), new("matched_conditions", "platform_health,detection_journal,low_disk", "rule") };
            e.AddRange(AnalystContext("The durable detection journal reported low disk/free-space risk.", "Severity is Critical because confirmed detections must never be lost due to local storage exhaustion.", "Replay tests on small lab disks can be expected, but production sensors require immediate remediation.", "Free disk space or move journal storage to a larger volume.", "Verify journal write health and retention policy after cleanup."));
            return MatchPlatformHealth(context, SeverityLevel.Critical, "Detection journal disk space low", "DetectionJournalDiskSpaceLow", e,
                c => { c.AddEvidence(0.34, "platform-health-anchor"); c.AddEvidence(0.30, "detection-journal-context"); c.AddEvidence(0.26, "low-disk-signal"); }, cooldownKey: journal);
        }
    }
}
