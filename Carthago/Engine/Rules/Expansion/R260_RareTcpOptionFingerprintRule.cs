// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R260_RareTcpOptionFingerprintRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R260_RareTcpOptionFingerprintRule : EvasionInfraPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R260",
            Name: "Rare TCP Option Fingerprint",
            Category: "EvasionInfra",
            Description: "Detects rare tcp option fingerprint only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R260.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvasionInfraProfile(
            ruleId: "R260",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_process_or_info" },
            evidenceFields: new[] { "network.source", "network.destination", "process.name", "event.info", "matched_conditions" },
            positiveConditions: new[]
            {
                "The rule must observe concrete telemetry evidence tied to the named behavior.",
                "The event must include a source and either a destination/host, process, protocol, or pipeline component.",
                "Generic descriptor text alone must not produce a match."
            },
            negativeConditions: new[]
            {
                "Do not alert when the required telemetry fields are absent.",
                "Do not alert on generic logs that mention the concept but lack network/process/pipeline evidence."
            },
            minimumConfidence: 75,
            threshold: 1,
            window: TimeSpan.FromMinutes(20),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+destination+behavior",
            falsePositives: new[] { "New operating systems, NAT devices, VPN clients, and legitimate scanners may introduce new TCP fingerprints." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "Threshold", "WindowSeconds" },
            requiredTests: new[] { "positive R260 evidence-gated sample", "negative R260 descriptor-only sample", "negative R260 missing telemetry sample" });

        public R260_RareTcpOptionFingerprintRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!(IsRareTcpOptionFingerprint(record, context, out var fingerprint)))
                return NoMatch();

            var count = 1;
            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "TcpFingerprint,evidence_gated,threshold_met", "rule"),
                new("rule.windowCount", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule")
            };
            if (!string.IsNullOrWhiteSpace(fingerprint)) evidence.Add(new DetectionEvidenceItem("tcp.optionFingerprint", fingerprint, "network"));
            evidence.AddRange(AnalystContext(
                "TCP option ordering/fingerprint was explicitly rare or new to the baseline for the same source/service context.",
                "Severity is Medium because unusual TCP option fingerprints may indicate custom tooling, scanners, OS spoofing, or evasion frameworks.",
                "New operating systems, NAT devices, VPN clients, and legitimate scanners may introduce new TCP fingerprints.",
                "Verify the source host role, owner, and recent process/startup changes.",
                "Pivot on destination host, destination port, process name, and adjacent detections in the same time window.",
                "Tune approved business systems explicitly instead of weakening the rule globally."));

            return MatchEvasionInfra(
                context,
                SeverityLevel.Medium,
                "Rare TCP option fingerprint observed for this source/service",
                "TcpFingerprint",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "concrete-evidence");
                    confidence.AddEvidence(0.22, "source-context");
                    confidence.AddEvidence(0.18, "threshold-or-baseline");
                },
                count: count,
                window: Profile.Window,
                cooldownKey: $"{record.Source}:{BestHost(record)}:{record.DestinationPort ?? 0}:TcpFingerprint");
        }
    }
}
