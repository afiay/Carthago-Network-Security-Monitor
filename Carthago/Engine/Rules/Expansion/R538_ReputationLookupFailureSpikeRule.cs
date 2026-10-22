// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R538_ReputationLookupFailureSpikeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R538_ReputationLookupFailureSpikeRule : PlatformHealthAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R538", "Reputation Lookup Failure Spike", "PlatformHealthAdvanced",
            "Detects reputation/enrichment lookup failure spikes from explicit health telemetry.", SeverityLevel.Low, "Rules.R538.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreatePlatformHealthProfile("R538", RulePrecisionMaturity.Validated, RuleRuntimeMode.Shadow,
            new[] { RuleTelemetryKind.Flow }, new[] { "platform_health_event", "reputation", "lookup_failure_signal" },
            new[] { "platform.windowCount", "matched_conditions" },
            new[] { "Reputation provider lookup failure must be explicit.", "A spike/surge signal or repeated lookup failures must be present." },
            new[] { "Do not alert on unknown reputation result alone.", "Do not alert when reputation lookups are intentionally disabled." },
            76, 6, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(30), "reputation-provider",
            new[] { "Provider rate limits, offline deployments, or disabled feeds can be expected." },
            new[] { "Mode", "Threshold", "WindowSeconds", "ProviderAllowlist" },
            new[] { "positive reputation lookup failure spike", "negative unknown reputation value" });
        public R538_ReputationLookupFailureSpikeRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record; var text = Text(r);
            if (!IsPlatformHealthRecord(r) || !ContainsAny(text, "reputation", "threat intel", "ioc lookup", "feed lookup", "enrichment")) return NoMatch();
            if (!ContainsAny(text, "lookup failure", "lookup failed", "provider failure", "rate limit", "timeout", "feed unavailable", "enrichment failed")) return NoMatch();
            var explicitSpike = ContainsAny(text, "spike", "surge", "burst", "excessive", "above baseline");
            var key = $"{Descriptor.RuleId}:{MetricKey(r)}"; var count = CountWindowEvents(key, context.TimestampUtc, TimeSpan.FromMinutes(10));
            if (!explicitSpike && count < 6) return NoMatch();
            var e = new List<DetectionEvidenceItem> { new("platform.windowCount", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "platform-health"), new("matched_conditions", explicitSpike ? "platform_health,reputation_failure,explicit_spike" : "platform_health,reputation_failure,window_threshold", "rule") };
            e.AddRange(AnalystContext("Reputation/threat-intel enrichment reported repeated lookup failures.", "Severity is Low because IOC context may degrade, but this does not prove malicious traffic.", "Rate limiting, feed outage, or planned offline operation can be benign.", "Check provider status, API keys, feed freshness, and rate-limit counters.", "Avoid promoting reputation-dependent rules until enrichment is healthy again."));
            return MatchPlatformHealth(context, SeverityLevel.Low, "Reputation lookup failure spike observed", "ReputationLookupFailureSpike", e,
                c => { c.AddEvidence(0.30, "platform-health-anchor"); c.AddEvidence(0.28, "reputation-context"); c.AddEvidence(0.24, "lookup-failure"); if (explicitSpike) c.AddEvidence(0.12, "explicit-spike"); }, count, TimeSpan.FromMinutes(10), key);
        }
    }
}
