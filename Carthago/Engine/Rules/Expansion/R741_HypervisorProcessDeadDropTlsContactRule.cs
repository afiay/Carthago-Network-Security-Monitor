// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R1739.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R741_HypervisorProcessDeadDropTlsContactRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R741",
            Name: "Hypervisor management process TLS contact to dead-drop service",
            Category: "EvasionTunnel",
            Description: "hostd, vpxa, or vmx is associated with outbound TLS/443 to a bounded paste/Gist text-storage service. Retrieved content, embedded secondary C2 indicators, response data and malicious intent are not observed.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R741.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R741",
            Name = "Hypervisor management process TLS contact to dead-drop service",
            Category = "EvasionTunnel",
            Description = "workbook.R1739: the source analytic describes dead-drop resolver behavior on ESXi. Carthago retains only exact hypervisor-management process attribution and a known dead-drop-service TLS SNI.",
            Severity = SeverityLevel.Low,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Tls, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "tls.sni", "tls.version", "process.name", "process.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed packet/parser fields and the exact local process/network predicate for this independent candidate.",
                "Correlated rules require unique packet IDs, monotonic UTC ordering and bounded rule-owned state.",
                "Only the observable request, TLS contact, connection attempt, packet burst or cadence is asserted."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, malformed endpoints and free-form Info-only evidence.",
                "Reject duplicate packet IDs, reverse time, expired windows and cooldown repeats.",
                "Do not infer file reads, command-line arguments, cron execution, upload completion, C2 control, proxy establishment, encoded content, DoS impact or compromise."
            },
            FalsePositives = new[] { "Support scripts, diagnostics, vendor tooling and administrator testing can legitimately access public text-storage services." },
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromSeconds(300),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+hypervisor_process+dead_drop_sni",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive shaped observation and independent benign near miss",
                "missing and contradictory telemetry",
                "duplicate IDs, reverse time and window expiry where stateful",
                "cooldown suppression and recovery",
                "fixed evidence privacy, non-convergence, Candidate Shadow and registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();

        public R741_HypervisorProcessDeadDropTlsContactRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research736Evidence.Tls443(r)
                || !Research736Evidence.HypervisorProcess(r)
                || !Research736Evidence.DeadDropHost(r.Sni))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1739", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "hypervisor_process_dead_drop_tls_sni", "rule"),
                new DetectionEvidenceItem("outcome", "dead_drop_service_contact_only_content_and_c2_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Low,
                "Hypervisor management-process TLS contact to a dead-drop service observed; retrieved content and secondary C2 semantics are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 1,
                windowSeconds: 300);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
