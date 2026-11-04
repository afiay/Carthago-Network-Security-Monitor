// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R1765.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R750_MacProcessCloudStorageTlsPayloadBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R750",
            Name: "macOS-characteristic process cloud-storage TLS payload burst",
            Category: "ExfiltrationAdvanced",
            Description: "osascript, Microsoft Word, Microsoft Excel, or Preview is associated with four substantial TLS/443 payload observations to a known cloud-storage SNI within two minutes. Local file reads, xattr changes, upload semantics, unique bytes and exfiltration are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R750.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R750",
            Name = "macOS-characteristic process cloud-storage TLS payload burst",
            Category = "ExfiltrationAdvanced",
            Description = "workbook.R1765: the source analytic correlates macOS document activity with web-service upload. Carthago keeps only macOS-characteristic process attribution, cloud-storage SNI and a bounded TLS payload burst.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Tls, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "tls.sni", "tls.version", "process.name", "process.id", "l4.length" },
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
            FalsePositives = new[] { "Document synchronization, cloud-drive collaboration, backup, DLP testing and enterprise productivity workflows can generate the same network shape." },
            MinimumConfidence = 82,
            WindowThreshold = 4,
            Window = TimeSpan.FromSeconds(120),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+mac_process+cloud_storage_sni+payload_burst",
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

        public R750_MacProcessCloudStorageTlsPayloadBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research746Evidence.Tls443(r)
                || !Research746Evidence.MacCloudProcess(r)
                || !Research716Evidence.CloudStorageHost(r.Sni)
                || r.L4Len is null or < 900 or > 8192
                || !_timed.Observe(r.Source + "|" + r.Sni + "|" + r.ProcessId,
                    r.Id, r.L4Len.Value, context.TimestampUtc, 4, false, 6000))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1765", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "mac_process_cloud_storage_tls_payload_burst", "rule"),
                new DetectionEvidenceItem("outcome", "cloud_storage_tls_burst_only_file_source_and_exfiltration_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "macOS-characteristic process cloud-storage TLS payload burst observed; file source, upload semantics, unique bytes and exfiltration are unknown.",
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
