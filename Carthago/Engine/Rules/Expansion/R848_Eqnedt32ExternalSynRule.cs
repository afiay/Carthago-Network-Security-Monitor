// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; no tests or builds executed. workbook.R2979.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R848_Eqnedt32ExternalSynRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R848", Name: "Equation Editor-attributed public HTTP-port SYN", Category: "EvasionInfra",
            Description: "Legacy Eqnedt32.exe process attributed to a public TCP/80 SYN; no document exploit, code injection or successful connection asserted.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R848.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R848", Name = "Equation Editor-attributed public HTTP-port SYN", Category = "EvasionInfra",
            Description = "workbook.R2979: Legacy Eqnedt32.exe process attributed to a public TCP/80 SYN; no document exploit, code injection or successful connection asserted.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] {
                "Coherent typed IPv4 packet predicate, unique identifiers and rule-owned bounded UTC observation.",
                "Only locally observed process or transport fields; no remote security outcome asserted."
            },
            NegativeConditions = new[] {
                "Missing/contradictory typed fields, duplicate IDs, reverse UTC time and stale state fail closed.",
                "No terminal login, decrypted content, file write, interface proof, authorization or actor inferred."
            },
            FalsePositives = new[] {
                "Administration, diagnostics, updates, sensor attribution errors and authorized security tests may share the observable pattern."
            },
            MinimumConfidence = 80, WindowThreshold = 1,
            Window = TimeSpan.FromSeconds(60), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "eqnedt32_public_80_syn",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] {
                "source-specific positive/benign cases", "missing and contradictory evidence",
                "duplicate, reverse and expiry", "cooldown recovery", "raw Info excluded",
                "neighboring rule non-convergence", "Candidate Shadow registration"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        
        public R848_Eqnedt32ExternalSynRule() : base(Rule, Profile) { }
        

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r) || !Research676Evidence.Syn(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || r.DestinationPort != 80 || !Research676Evidence.Process(r, "eqnedt32.exe")) return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[] {
                new DetectionEvidenceItem("research.identifier", "workbook.R2979", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "eqnedt32_public_80_syn", "rule"),
                new DetectionEvidenceItem("outcome", "typed_observation_only_attribution_and_security_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Equation Editor-attributed public HTTP-port SYN observed; process provenance, authorization, causality and outcome unknown.",
                evidence, confidence => {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_signal");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 1, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

