// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R530_SensorClockSkewIncreasingRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R530_SensorClockSkewIncreasingRule : PlatformHealthAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R530", "Sensor Clock Skew Increasing", "PlatformHealthAdvanced",
            "Detects explicit sensor clock-skew drift reported by platform health telemetry.", SeverityLevel.Medium, "Rules.R530.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreatePlatformHealthProfile("R530", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert,
            new[] { RuleTelemetryKind.Flow }, new[] { "platform_health_event", "sensor", "clock_skew_signal" },
            new[] { "sensor.id", "matched_conditions" },
            new[] { "The event must explicitly reference sensor time, clock skew, drift, or NTP sync problems.", "The event must indicate increasing/above-threshold skew." },
            new[] { "Do not alert on ordinary NTP traffic.", "Do not alert on one timestamp that is merely old in captured traffic." },
            82, 1, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(30), "sensor",
            new[] { "Lab VMs resuming from sleep can trigger skew until NTP catches up." },
            new[] { "Mode", "CooldownSeconds", "ClockSkewThresholdMs" },
            new[] { "positive sensor clock skew increasing", "negative ordinary ntp packet" });
        public R530_SensorClockSkewIncreasingRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // GA R529-R530 — SOURCE CANDIDATE — UNVERIFIED.
            // IsPlatformHealthRecord relies on mutable text fields and is not
            // an authenticated sensor-health producer. Preserve the original
            // evaluation path for a future typed integration, but fail closed
            // until the trusted producer is actually connected.
            var missingProducer = EvasionAndSensorEvidenceBoundary.GetMissingProducer(Descriptor.RuleId);
            if (missingProducer is { } missing)
                return RuleEvaluationResult.NoMatch(Descriptor.RuleId,
                    RuleNoMatchReasonCategory.InsufficientEvidence, missing.Code, missing.Detail);

            var r = context.Record; var text = Text(r);
            if (!IsPlatformHealthRecord(r) || !ContainsAny(text, "clock skew", "time skew", "clock drift", "time drift", "ntp sync", "timestamp drift")) return NoMatch();
            if (!ContainsAny(text, "increasing", "above threshold", "exceeded", "drift", "unsynchronized", "out of sync", "out-of-sync")) return NoMatch();
            var sensor = MetricKey(r);
            var e = new List<DetectionEvidenceItem> { new("sensor.id", sensor, "platform-health"), new("matched_conditions", "platform_health,sensor_clock_skew,increasing", "rule") };
            e.AddRange(AnalystContext("Sensor health reported increasing clock skew or loss of time synchronization.", "Severity is Medium because timestamp skew can break correlation windows, baselines, and incident timelines.", "VM sleep/resume and lab hosts without stable NTP can be benign but should be fixed for reliable detections.", "Check NTP configuration and host clock sync.", "Review correlation windows for incidents from this sensor during the skew period."));
            return MatchPlatformHealth(context, SeverityLevel.Medium, "Sensor clock skew increasing", "SensorClockSkewIncreasing", e,
                c => { c.AddEvidence(0.32, "platform-health-anchor"); c.AddEvidence(0.28, "clock-skew-context"); c.AddEvidence(0.22, "increasing-or-threshold-signal"); }, cooldownKey: sensor);
        }
    }
}
