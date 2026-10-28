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

        private readonly NetworkBatch256260Evidence.FingerprintChange _changes = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch256260Evidence.SynFingerprint(r, out var fingerprint)) return NoMatch();
            var key = r.Source + "|" + r.Destination + "|" + r.DestinationPort;
            if (!_changes.Observe(r, context.TimestampUtc, key, fingerprint)) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "typed_ja4t_syn_fingerprint,instance_observed_change", "rule"),
                new("tcp.fingerprintStatus", "changed_from_instance_first_not_approved_baseline", "rule"),
                new("tcp.fingerprintKey", NetworkBatch131135Evidence.Fingerprint(fingerprint), "network")
            };
            evidence.AddRange(AnalystContext("The SYN JA4T value changed relative to this detector instance's first observation.",
                "Change does not establish statistical rarity or malicious tooling.",
                "OS updates, NAT and path changes can alter SYN fingerprints.",
                "Compare with an approved fingerprint baseline before escalation."));
            return MatchEvasionInfra(context, SeverityLevel.Medium,
                "SYN fingerprint changed from instance-first observation (rarity unverified)",
                "TcpFingerprint", evidence,
                c => { c.AddEvidence(0.34, "typed-ja4t"); c.AddEvidence(0.22, "same-source-service"); c.AddEvidence(0.18, "instance-change"); },
                cooldownKey: key + ":tcp-fingerprint-change");
        }
    }
}
