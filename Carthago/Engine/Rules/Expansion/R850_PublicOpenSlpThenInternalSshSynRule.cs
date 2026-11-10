// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; no tests or builds executed. workbook.R1116.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R850_PublicOpenSlpThenInternalSshSynRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R850", Name: "Public OpenSLP ingress SYN then internal SSH SYN", Category: "LateralMovement",
            Description: "A public TCP SYN targets private OpenSLP/427, followed by that private host initiating an internal TCP/22 SYN within 60s; no ESXi identity or exploitation proven.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R850.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R850", Name = "Public OpenSLP ingress SYN then internal SSH SYN", Category = "LateralMovement",
            Description = "workbook.R1116: A public TCP SYN targets private OpenSLP/427, followed by that private host initiating an internal TCP/22 SYN within 60s; no ESXi identity or exploitation proven.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "packet.id" },
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
            MinimumConfidence = 80, WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(60), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "public_openslp_ingress_then_private_ssh_syn",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] {
                "source-specific positive/benign cases", "missing and contradictory evidence",
                "duplicate, reverse and expiry", "cooldown recovery", "raw Info excluded",
                "neighboring rule non-convergence", "Candidate Shadow registration"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R850_PublicOpenSlpThenInternalSshSynRule() : base(Rule, Profile) { }
        

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (Research786NetworkEvidence.Coherent(r) && Research676Evidence.Syn(r) && Research786NetworkEvidence.PublicPrivate(r)
                && r.DestinationPort == 427)
            {
                _stages.Observe(r.Destination!, r.Id, context.TimestampUtc, true, 60);
                return NoMatch();
            }
            if (!Research786NetworkEvidence.Coherent(r) || !Research676Evidence.Syn(r) || !Research786NetworkEvidence.Internal(r)
                || r.DestinationPort != 22
                || !_stages.Observe(r.Source!, r.Id, context.TimestampUtc, false, 60)) return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[] {
                new DetectionEvidenceItem("research.identifier", "workbook.R1116", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "public_openslp_ingress_then_private_ssh_syn", "rule"),
                new DetectionEvidenceItem("outcome", "typed_observation_only_attribution_and_security_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Public OpenSLP ingress SYN then internal SSH SYN observed; process provenance, authorization, causality and outcome unknown.",
                evidence, confidence => {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_signal");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 2, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

