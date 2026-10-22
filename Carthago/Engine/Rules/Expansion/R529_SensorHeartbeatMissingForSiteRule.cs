// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R529_SensorHeartbeatMissingForSiteRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R529_SensorHeartbeatMissingForSiteRule : PlatformHealthAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R529", "Sensor Heartbeat Missing For Site", "PlatformHealthAdvanced",
            "Detects explicit health-monitor telemetry showing that a site/sensor heartbeat is missing or overdue; it never infers absence from a single traffic record.", SeverityLevel.High, "Rules.R529.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreatePlatformHealthProfile("R529", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert,
            new[] { RuleTelemetryKind.Flow }, new[] { "platform_health_event", "sensor_or_site", "heartbeat_missing_signal" },
            new[] { "sensor.id", "site.id", "matched_conditions" },
            new[] { "A sensor/site health monitor must explicitly report missing/overdue heartbeat.", "The event should identify a sensor, site, or capture source." },
            new[] { "Do not infer missing heartbeat from lack of network traffic.", "Do not alert during known maintenance or intentionally disabled sensors." },
            86, 1, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(20), "site+sensor",
            new[] { "Planned maintenance, lab shutdowns, or disabled sensors can be legitimate." },
            new[] { "Mode", "CooldownSeconds", "MaintenanceWindow", "HeartbeatGraceSeconds" },
            new[] { "positive heartbeat missing health event", "negative quiet network period" });
        public R529_SensorHeartbeatMissingForSiteRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record; var text = Text(r);
            if (!IsPlatformHealthRecord(r) || !ContainsAny(text, "heartbeat", "sensor health", "site health")) return NoMatch();
            if (!ContainsAny(text, "missing", "overdue", "lost", "stale", "timeout", "not received")) return NoMatch();
            if (ContainsAny(text, "maintenance", "disabled", "expected offline", "decommissioned")) return NoMatch();
            var sensor = MetricKey(r);
            var e = new List<DetectionEvidenceItem> { new("sensor.id", sensor, "platform-health"), new("matched_conditions", "platform_health,sensor_heartbeat,missing", "rule") };
            e.AddRange(AnalystContext("A health monitor reported that a sensor/site heartbeat is missing or stale.", "Severity is High because the detector may lose visibility for that site or capture source.", "Maintenance and intentionally disabled sensors should be represented as explicit suppressions.", "Check sensor process, host uptime, capture interface, and network path.", "Confirm whether detections for that site stopped at the same time."));
            return MatchPlatformHealth(context, SeverityLevel.High, "Sensor heartbeat missing for site", "SensorHeartbeatMissing", e,
                c => { c.AddEvidence(0.34, "platform-health-anchor"); c.AddEvidence(0.28, "heartbeat-context"); c.AddEvidence(0.24, "missing-or-stale-signal"); }, cooldownKey: sensor);
        }
    }
}
