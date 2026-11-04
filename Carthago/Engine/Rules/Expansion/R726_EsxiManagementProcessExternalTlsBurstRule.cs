// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook workbook.R1159.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R726_EsxiManagementProcessExternalTlsBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R726",
            Name: "ESXi management process external TLS payload burst",
            Category: "ExfiltrationAdvanced",
            Description: "hostd, vpxa, or vmx is associated with four substantial TLS/443 payload observations to one public peer within two minutes. Packet lengths are not unique transferred bytes and do not prove datastore reads, uploads, web-service use, exfiltration, or compromise.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R726.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R726",
            Name = "ESXi management process external TLS payload burst",
            Category = "ExfiltrationAdvanced",
            Description = "workbook.R1159: the source analytic expects ESXi management/guest processes making unexpected external HTTPS transfers with significant data. Carthago keeps only exact process attribution plus a bounded TLS payload burst.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Tls, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "tls.sni", "tls.version", "process.name", "process.id", "l4.length" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed packet fields plus the exact process/network predicate defined by this independent candidate.",
                "Correlated rules accept only unique packet IDs in monotonic UTC order inside a bounded rule-owned window.",
                "Only the observed process association, network shape, request classification or packet burst is asserted."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, invalid endpoints and free-form Info-only assertions.",
                "Reject duplicate packet IDs, reverse time, expired windows and cooldown repeats.",
                "Do not infer command-line arguments, asset role, file access, successful transfer, authenticated endpoint state, C2, DoS impact, exploit success or compromise."
            },
            FalsePositives = new[] { "Patch management, backup, telemetry, VMware support tooling, content distribution and administrator workflows can legitimately create external TLS traffic from ESXi-associated processes." },
            MinimumConfidence = 82,
            WindowThreshold = 4,
            Window = TimeSpan.FromSeconds(120),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+esxi_process+public_tls_peer+payload_burst",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive real-life-shaped sample and benign near miss",
                "missing and contradictory telemetry",
                "duplicate ID, reverse time and window expiry for correlated candidates",
                "cooldown suppression and recovery",
                "fixed evidence privacy, Candidate Shadow and unique registry"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research666TimedWindow _timed = new();

        public R726_EsxiManagementProcessExternalTlsBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research726Evidence.Tls443(r)
                || !Research726Evidence.EsxiProcess(r)
                || r.L4Len is null or < 900 or > 8192
                || !_timed.Observe(r.Source + "|" + r.Destination + "|" + r.ProcessId,
                    r.Id, r.L4Len.Value, context.TimestampUtc, 4, false, 5000))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1159", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "esxi_management_process_external_tls_payload_burst", "rule"),
                new DetectionEvidenceItem("outcome", "external_tls_payload_burst_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "ESXi management-process external TLS payload burst observed; transferred content, unique bytes, upload semantics and security outcome are unknown.",
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
