// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R1477.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R748_LinuxCryptoToolUncommonPortPayloadBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R748",
            Name: "Linux crypto-tool uncommon-port payload burst",
            Category: "ExfiltrationAdvanced",
            Description: "openssl, gpg, gpg2, or age is associated with four substantial raw TCP payload observations to one public uncommon port within two minutes. Encryption invocation, key material, file source, delivered bytes and exfiltration are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R748.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R748",
            Name = "Linux crypto-tool uncommon-port payload burst",
            Category = "ExfiltrationAdvanced",
            Description = "workbook.R1477: the source analytic correlates symmetric-encryption utilities with external transfer. Carthago cannot observe the encoder command line or file input, so this rule requires only an exact crypto-tool basename and a bounded uncommon-port payload burst.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "destination.port", "process.name", "process.id", "l4.length" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed packet/parser fields plus the exact best-effort local process/network predicate for this candidate.",
                "Stateful predicates require unique packet IDs, monotonic UTC observations and bounded rule-owned state.",
                "Only the observed connection, request, packet burst, service host or two-stage network sequence is asserted."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, malformed endpoints and free-form Info-only assertions.",
                "Reject duplicate packet IDs, reverse time, expired windows and cooldown repeats.",
                "Do not infer file reads, encryption execution, command-line arguments, upload completion, authentication, exploit success, C2, lateral compromise or data loss."
            },
            FalsePositives = new[] { "Key management, package signing, certificate diagnostics, encrypted backup and developer tooling can legitimately create uncommon-port connections from crypto utilities." },
            MinimumConfidence = 82,
            WindowThreshold = 4,
            Window = TimeSpan.FromSeconds(120),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+crypto_tool+public_uncommon_port+payload_burst",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive real-life-shaped sample and rule-specific benign near miss",
                "missing and contradictory producer fields",
                "duplicate IDs, reverse time and expiry for correlated candidates",
                "cooldown suppression and recovery",
                "evidence privacy, non-convergence, Candidate Shadow and registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research666TimedWindow _timed = new();

        public R748_LinuxCryptoToolUncommonPortPayloadBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research746Evidence.UncommonRawPayload(r)
                || !Research746Evidence.LinuxCryptoProcess(r)
                || r.L4Len is null or < 700 or > 8192
                || !_timed.Observe(r.Source + "|" + r.Destination + "|" + r.DestinationPort + "|" + r.ProcessId,
                    r.Id, r.L4Len.Value, context.TimestampUtc, 4, false, 4000))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1477", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "linux_crypto_tool_uncommon_port_payload_burst", "rule"),
                new DetectionEvidenceItem("outcome", "crypto_process_network_burst_only_encryption_and_exfiltration_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Crypto-tool uncommon-port payload burst observed; encryption operation, key/file source, delivered bytes and exfiltration are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 4,
                windowSeconds: 120);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
