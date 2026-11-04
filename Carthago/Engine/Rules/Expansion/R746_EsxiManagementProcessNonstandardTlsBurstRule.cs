// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R1149.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R746_EsxiManagementProcessNonstandardTlsBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R746",
            Name: "ESXi management-process nonstandard-port TLS payload burst",
            Category: "ExfiltrationAdvanced",
            Description: "hostd, vpxa, or vmx is associated with four substantial TLS payload observations to one public peer on a bounded nonstandard TLS port within two minutes. Encryption algorithm, file source, unique TCP bytes, upload semantics and exfiltration are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R746.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R746",
            Name = "ESXi management-process nonstandard-port TLS payload burst",
            Category = "ExfiltrationAdvanced",
            Description = "workbook.R1149: the source analytic describes encrypted non-C2 egress from ESXi management services. Carthago keeps exact hypervisor-process attribution, a typed TLS handshake on a nonstandard port, and a bounded payload burst.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Tls, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "destination.port", "tls.sni", "tls.version", "process.name", "process.id", "l4.length" },
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
            FalsePositives = new[] { "VMware support tooling, custom management gateways, backup products and vendor services can legitimately use TLS on nonstandard ports." },
            MinimumConfidence = 82,
            WindowThreshold = 4,
            Window = TimeSpan.FromSeconds(120),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+esxi_process+public_nonstandard_tls_peer+payload_burst",
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

        public R746_EsxiManagementProcessNonstandardTlsBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research746Evidence.NonstandardTls(r)
                || !Research746Evidence.HypervisorProcess(r)
                || r.L4Len is null or < 900 or > 8192
                || !_timed.Observe(r.Source + "|" + r.Destination + "|" + r.DestinationPort + "|" + r.ProcessId,
                    r.Id, r.L4Len.Value, context.TimestampUtc, 4, false, 5000))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1149", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "esxi_management_process_nonstandard_tls_payload_burst", "rule"),
                new DetectionEvidenceItem("outcome", "tls_payload_burst_only_crypto_and_exfiltration_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "ESXi management-process nonstandard-port TLS payload burst observed; crypto operation, file source, unique bytes and exfiltration are unknown.",
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
