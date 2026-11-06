// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R2751.
using System;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R761_RmmProcessExternalTlsCadenceRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R761",
            Name: "RMM process recurrent external TLS cadence",
            Category: "RemoteAccess",
            Description: "TeamViewer, AnyDesk, or ScreenConnect/ConnectWise Control process attribution is associated with three similarly sized TLS/443 payload observations to one public peer at 10–60 second intervals. Installation, firewall changes, session establishment, operator identity and malicious use are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R761.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R761",
            Name = "RMM process recurrent external TLS cadence",
            Category = "RemoteAccess",
            Description = "workbook.R2751: the source analytic combines remote-management software execution with outbound beaconing and session evidence. Carthago retains exact RMM process attribution plus a bounded recurrent TLS cadence.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Tls, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "tls.sni", "tls.version", "process.name", "process.id", "l4.length" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed producer fields and this independent rule-specific predicate.",
                "Process identity, where used, is best-effort local tuple enrichment rather than authenticated endpoint identity.",
                "Stateful rules accept unique packet IDs in monotonic UTC order inside bounded rule-owned windows."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, malformed endpoints and Info-only assertions.",
                "Reject duplicate packet IDs, reverse time, expired sequences and cooldown repeats.",
                "Do not infer file access, credentials, command-line arguments, successful authentication, exploit success, C2 control, transfer completion or compromise."
            },
            FalsePositives = new[] { "Authorized remote support, help-desk tooling, unattended administration and managed-service-provider agents commonly produce recurrent TLS traffic." },
            MinimumConfidence = 82,
            WindowThreshold = 3,
            Window = TimeSpan.FromSeconds(120),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+rmm_process+public_tls_peer+cadence",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive shaped sample and rule-specific benign near miss",
                "missing and contradictory telemetry",
                "duplicate ID, reverse-time and expiry where stateful",
                "cooldown suppression and recovery",
                "privacy, non-convergence, Candidate Shadow and registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research736CadenceWindow _cadence = new();

        public R761_RmmProcessExternalTlsCadenceRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research756Evidence.RmmTlsPayload(r)
                || !_cadence.Observe(r.Source + "|" + r.Destination + "|" + r.ProcessId,
                    r.Id, r.L4Len!.Value, context.TimestampUtc, 3, 10, 60, 150, 120))
                return NoMatch();

            var cool = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (cool == WebSignatureObservation.None) return NoMatch();
            if (cool == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2751", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "rmm_process_recurrent_external_tls_cadence", "rule"),
                new DetectionEvidenceItem("outcome", "rmm_tls_cadence_only_session_and_intent_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "RMM process recurrent external TLS cadence observed; installation state, remote session establishment, operator identity and intent are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 3,
                windowSeconds: 120);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
