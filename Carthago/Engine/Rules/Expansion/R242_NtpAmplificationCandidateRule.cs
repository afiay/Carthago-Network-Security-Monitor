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

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasNtpAmplificationSemantics(record))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 120, 30, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 5, 2, 1000);
            var count = CountWindowEvents($"{Descriptor.RuleId}:{record.Source}:{record.Destination}", context.TimestampUtc, window);
            if (count < threshold)
                return NoMatch();

            var external = IsExternalAddress(record.Source) || IsExternalAddress(record.Destination);
            var evidence = new List<DetectionEvidenceItem>
            {
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", external ? "udp_ntp,amplification_command_semantics,external_context,burst_threshold" : "udp_ntp,amplification_command_semantics,burst_threshold", "rule")
            };
            evidence.AddRange(AnalystContext(
                "NTP traffic carried amplification-prone command semantics repeatedly within a short window.",
                "Severity is Medium because monlist/mode7/readvar-style traffic can indicate reflection/amplification probing or abuse of exposed NTP services.",
                "Approved scanners may intentionally test NTP amplification posture.",
                "Confirm whether the source is an approved vulnerability scanner or monitoring host.",
                "Check whether the NTP service is internet-exposed and whether legacy monlist/mode7 behavior is enabled."));

            return MatchIot(
                context,
                SeverityLevel.Medium,
                "NTP amplification candidate traffic observed",
                "NtpAmplification",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "ntp-amplification-semantics");
                    confidence.AddEvidence(0.20, "burst-threshold");
                    if (external) confidence.AddCorrelation(0.10, "external-context");
                },
                count,
                window,
                $"{record.Source}:{record.Destination}:ntp-amplification");
        }
    }
}
