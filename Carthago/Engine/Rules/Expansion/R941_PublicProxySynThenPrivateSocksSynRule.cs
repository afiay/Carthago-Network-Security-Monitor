// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. workbook.R1925; xUnit source authored first.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R941_PublicProxySynThenPrivateSocksSynRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R941", Name: "Public proxy ingress then private SOCKS-port SYN", Category: "CommandAndControl",
            Description: "Public TCP/3128 SYN to a private host followed by that host initiating TCP/1080 SYN to another private peer within 45s. Proxy setup, forwarding configuration and actual relay are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R941.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R941", Name = "Public proxy ingress then private SOCKS-port SYN", Category = "CommandAndControl",
            Description = "workbook.R1925: Public TCP/3128 SYN to a private host followed by that host initiating TCP/1080 SYN to another private peer within 45s. Proxy setup, forwarding configuration and actual relay are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "tcp.flags" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Public TCP/3128 SYN to a private host followed by that host initiating TCP/1080 SYN to another private peer within 45s. Proxy setup, forwarding configuration and actual relay are unknown.", "Coherent typed IPv4 fields and independent bounded UTC observations." },
            NegativeConditions = new[] { "Wrong endpoints, missing or contradictory typed evidence, duplicate IDs, reverse UTC or expired windows fail closed.",
                "No unsupported endpoint action, authenticated session, authorization or security outcome inferred." },
            FalsePositives = new[] { "Authorized administration, maintenance, deployment and diagnostics may share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "R941_PublicProxySynThenPrivateSocksSynRule",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory fields", "duplicate and reverse UTC", "correlation expiry and isolation", "cooldown recovery", "raw Info excluded", "independent state and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R941_PublicProxySynThenPrivateSocksSynRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            var first = Research676Evidence.Syn(r) && Research786NetworkEvidence.PublicPrivate(r) && r.DestinationPort == 3128 && r.Sni == null && r.HttpUri == null && !r.DnsIsResponse;
            var second = Research676Evidence.Syn(r) && Research786NetworkEvidence.Internal(r) && r.DestinationPort == 1080 && r.Sni == null && r.HttpUri == null && !r.DnsIsResponse && r.Source != r.Destination;
            if (!first && !second) return NoMatch();
            var key = first ? r.Destination! : r.Source!;
            if (!_stages.Observe(key, r.Id, context.TimestampUtc, first, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1925", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "R941_PublicProxySynThenPrivateSocksSynRule", "rule"),
                new DetectionEvidenceItem("outcome", "typed_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Public proxy ingress then private SOCKS-port SYN observed; authorization, causality and outcome remain unverified.", evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "specific_workbook_observable_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 2, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
