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
            distinctBy: "unique_frame",
            falsePositives: new[] { "Approved engineering or device commissioning tools can intentionally enumerate Profinet devices." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[] { "positive profinet discovery burst sample", "negative single profinet request sample" });

        public R227_ProfinetDcpDiscoverySuspiciousRule() : base(Rule, Profile) { }

        // The IP-only capture path cannot observe Ethernet DCP frames yet.
        // Only explicitly decoded L2 records are eligible; never substitute UDP/34964.
        private readonly NetworkBatch226230Evidence.Window _observations = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch226230Evidence.ProfinetDcp(r)) return NoMatch();
            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 120, 30, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 8, 3, 500);
            var count = _observations.Observe(r.MacSource, r.MacDestination, r.Id, context.TimestampUtc, window, false);
            if (count < threshold) return NoMatch();
            return MatchIot(context, SeverityLevel.Medium, "Decoded Profinet DCP Identify burst",
                "Profinet DCP",
                new[] { new DetectionEvidenceItem("count", count.ToString(), "rule"),
                    new DetectionEvidenceItem("matched_conditions", "typed_l2_dcp_identify,unique_frame_burst", "rule") },
                confidence => { confidence.AddEvidence(0.28, "typed-l2-dcp-identify");
                    confidence.AddEvidence(0.20, "unique-frame-burst"); },
                count, window, r.MacSource + ":profinet-discovery");
        }
    }
}
