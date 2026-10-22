// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R537_GeoIPLookupFailureSpikeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R537_GeoIPLookupFailureSpikeRule : PlatformHealthAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R537", "GeoIP Lookup Failure Spike", "PlatformHealthAdvanced",
            "Detects GeoIP enrichment failure spikes from explicit platform-health telemetry, not from ordinary missing country fields.",
            SeverityLevel.Low, "Rules.R537.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreatePlatformHealthProfile("R537", RulePrecisionMaturity.Validated, RuleRuntimeMode.Shadow,
            new[] { RuleTelemetryKind.GeoIp, RuleTelemetryKind.Flow }, new[] { "platform_health_event", "geoip", "lookup_failure_signal" },
            new[] { "platform.windowCount", "matched_conditions" },
            new[] { "GeoIP lookup or enrichment failure must be explicit.", "A spike/surge signal or repeated lookup failures must be present." },
            new[] { "Do not alert on private IPs, RFC1918 addresses, or a single record without GeoIP enrichment.", "Do not alert on offline environments where GeoIP is intentionally disabled." },
            76, 6, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(30), "geoip-provider",
            new[] { "Air-gapped labs and disabled GeoIP enrichment are expected sources of benign failures." },
            new[] { "Mode", "Threshold", "WindowSeconds", "GeoIpEnabled" },
            new[] { "positive geoip lookup failure spike", "negative missing geo field on private ip" });
        public R537_GeoIPLookupFailureSpikeRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record; var text = Text(r);
            if (!IsPlatformHealthRecord(r) || !ContainsAny(text, "geoip", "geo ip", "geolocation")) return NoMatch();
            if (!ContainsAny(text, "lookup failure", "lookup failed", "enrichment failed", "provider failure", "database unavailable", "maxmind")) return NoMatch();
            var explicitSpike = ContainsAny(text, "spike", "surge", "burst", "excessive", "above baseline");
            var key = $"{Descriptor.RuleId}:{MetricKey(r)}"; var count = CountWindowEvents(key, context.TimestampUtc, TimeSpan.FromMinutes(10));
            if (!explicitSpike && count < 6) return NoMatch();
            var e = new List<DetectionEvidenceItem> { new("platform.windowCount", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "platform-health"), new("matched_conditions", explicitSpike ? "platform_health,geoip_failure,explicit_spike" : "platform_health,geoip_failure,window_threshold", "rule") };
            e.AddRange(AnalystContext("GeoIP enrichment reported repeated lookup failures.", "Severity is Low because detection still works, but geo/country-based precision and context may degrade.", "Offline deployments or intentionally disabled GeoIP enrichment can be legitimate.", "Check GeoIP database/provider availability.", "Confirm whether country-based rules should temporarily run in shadow mode."));
            return MatchPlatformHealth(context, SeverityLevel.Low, "GeoIP lookup failure spike observed", "GeoIPLookupFailureSpike", e,
                c => { c.AddEvidence(0.30, "platform-health-anchor"); c.AddEvidence(0.28, "geoip-context"); c.AddEvidence(0.24, "lookup-failure"); if (explicitSpike) c.AddEvidence(0.12, "explicit-spike"); }, count, TimeSpan.FromMinutes(10), key);
        }
    }
}
