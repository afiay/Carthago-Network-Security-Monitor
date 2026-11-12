// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Test source authored first; no build/test execution. workbook.R2642.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R917_PrivateRdpThenOtherHostWinRmSynRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R917", Name: "Private RDP ingress then private WinRM SYN", Category: "LateralMovement",
            Description: "Private TCP/3389 SYN to private host followed by that host sending TCP/5985 SYN to another private peer. ICS role, approved matrix, login and execution are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R917.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R917", Name = "Private RDP ingress then private WinRM SYN", Category = "LateralMovement",
            Description = "workbook.R2642: Private TCP/3389 SYN to private host followed by that host sending TCP/5985 SYN to another private peer. ICS role, approved matrix, login and execution are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "tcp.flags" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Private TCP/3389 SYN to private host followed by that host sending TCP/5985 SYN to another private peer. ICS role, approved matrix, login and execution are unknown.", "Coherent typed IPv4 fields and bounded UTC observations." },
            NegativeConditions = new[] { "Missing or contradictory evidence, mismatched keys, duplicate packet IDs, reverse UTC and expired windows fail closed.",
                "No unsupported host identity, execution, authentication, authorization or security outcome inferred." },
            FalsePositives = new[] { "Authorized administration, diagnostics, software deployment, maintenance and security testing can share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "R917_PrivateRdpThenOtherHostWinRmSynRule",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory fields", "duplicate and reverse UTC",
                "correlation expiry and key isolation", "cooldown recovery", "raw Info exclusion", "neighbor independence", "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R917_PrivateRdpThenOtherHostWinRmSynRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            var first = Research786NetworkEvidence.Internal(r) && r.DestinationPort == 3389 && r.Source != r.Destination && Research676Evidence.Syn(r) && r.Sni == null && r.HttpUri == null && !r.DnsIsResponse;
            var second = Research786NetworkEvidence.Internal(r) && r.DestinationPort == 5985 && r.Source != r.Destination && Research676Evidence.Syn(r) && r.Sni == null && r.HttpUri == null && !r.DnsIsResponse;
            if (!first && !second) return NoMatch();
            var key = first ? r.Destination! : r.Source!;
            if (!_stages.Observe(key, r.Id, context.TimestampUtc, first, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2642", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "R917_PrivateRdpThenOtherHostWinRmSynRule", "rule"),
                new DetectionEvidenceItem("outcome", "typed_network_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Private RDP ingress then private WinRM SYN observed; authorization, causality and outcome remain unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "specific_workbook_observable_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 2, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
