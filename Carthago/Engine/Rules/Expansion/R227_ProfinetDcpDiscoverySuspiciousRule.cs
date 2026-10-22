// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R227_ProfinetDcpDiscoverySuspiciousRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R227_ProfinetDcpDiscoverySuspiciousRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R227",
            Name: "Profinet DCP Discovery Suspicious",
            Category: "IotOtAdvanced",
            Description: "Detects suspicious bursts of Profinet DCP identify requests, rather than any generic Profinet or DCP mention.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R227.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R227",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            requiredFields: new[] { "source", "destination_or_host", "iot_or_ot_context" },
            evidenceFields: new[] { "count", "window_seconds", "matched_conditions" },
            positiveConditions: new[]
            {
                "The record must contain real Profinet DCP discovery semantics such as identify-all or station-name discovery.",
                "The same source should hit many destinations in a short window.",
                "Single routine Profinet exchanges should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on generic Profinet traffic without discovery semantics.",
                "Do not alert on isolated discovery."
            },
            minimumConfidence: 76,
            threshold: 8,
            window: TimeSpan.FromMinutes(2),
            cooldown: TimeSpan.FromMinutes(15),
            distinctBy: "destination",
            falsePositives: new[] { "Approved engineering or device commissioning tools can intentionally enumerate Profinet devices." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[] { "positive profinet discovery burst sample", "negative single profinet request sample" });

        public R227_ProfinetDcpDiscoverySuspiciousRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsProfinetContext(record) || !HasProfinetDiscoverySemantics(record))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 120, 30, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 8, 3, 500);
            var count = CountDistinctValues($"{Descriptor.RuleId}:{record.Source}", record.Destination ?? BestHost(record), context.TimestampUtc, window);
            if (count < threshold)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", "profinet_dcp_discovery,destination_burst_threshold", "rule")
            };
            evidence.AddRange(AnalystContext(
                "Profinet DCP discovery semantics were sent to many distinct destinations in a short window.",
                "Severity is Medium because high-rate device identification across Profinet networks often indicates reconnaissance or unaudited commissioning scans.",
                "Approved engineering or device commissioning workflows can resemble this pattern.",
                "Validate whether the source is a sanctioned commissioning or engineering host.",
                "Review the destination spread and whether identify-all or station-name discovery aligned with maintenance activity."));

            return MatchIot(
                context,
                SeverityLevel.Medium,
                "Profinet DCP discovery burst observed",
                "Profinet DCP",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.28, "profinet-dcp-discovery");
                    confidence.AddEvidence(0.20, "destination-burst-threshold");
                },
                count,
                window,
                $"{record.Source}:profinet-discovery");
        }
    }
}
