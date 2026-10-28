// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R242_NtpAmplificationCandidateRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R242_NtpAmplificationCandidateRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R242",
            Name: "NTP Amplification Candidate",
            Category: "IotOtAdvanced",
            Description: "Detects NTP amplification candidate traffic only when UDP/NTP and amplification-prone command semantics such as monlist/mode7/readvar are present.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R242.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R242",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow },
            requiredFields: new[] { "udp", "ntp_port", "amplification_semantics" },
            evidenceFields: new[] { "count", "window_seconds", "matched_conditions" },
            positiveConditions: new[]
            {
                "The traffic must be UDP/NTP on port 123 or explicit NTP application context.",
                "Amplification-prone semantics such as monlist, ntpdc mode 7, readvar, or read variables must be present.",
                "Repeated attempts within a window increase confidence."
            },
            negativeConditions: new[]
            {
                "Do not alert on normal time synchronization.",
                "Do not alert on NTP port traffic without amplification-prone command semantics."
            },
            minimumConfidence: 80,
            threshold: 5,
            window: TimeSpan.FromMinutes(2),
            cooldown: TimeSpan.FromMinutes(15),
            distinctBy: "source+destination",
            falsePositives: new[] { "Security scanners and NTP health checks may test monlist/readvar; approved scanners should be tuned." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedScanners" },
            requiredTests: new[] { "positive ntp monlist burst sample", "negative normal ntp sync sample" });

        public R242_NtpAmplificationCandidateRule() : base(Rule, Profile) { }

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch241245Evidence.NtpMonlist(r)) return NoMatch();
            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 120, 30, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 5, 2, 1000);
            var count = _observations.Observe(r.Source + ":" + r.Destination, "ntp-monlist", r.Id,
                context.TimestampUtc, window, false);
            if (count < threshold) return NoMatch();
            return MatchIot(context, SeverityLevel.Medium, "Parsed NTP mode-7 monlist request burst observed",
                "NtpAmplification", new[] {
                    new DetectionEvidenceItem("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                    new DetectionEvidenceItem("window_seconds", ((int)window.TotalSeconds).ToString(), "rule"),
                    new DetectionEvidenceItem("matched_conditions", "udp_ntp,parsed_mode7_monlist,packet_burst", "rule")
                }, confidence => { confidence.AddEvidence(0.34, "parsed-monlist"); confidence.AddEvidence(0.20, "packet-burst"); confidence.AddCorrelation(0.10, "ntp-target"); }, count, window,
                r.Source + ":" + r.Destination + ":ntp-monlist");
        }

    }
}
