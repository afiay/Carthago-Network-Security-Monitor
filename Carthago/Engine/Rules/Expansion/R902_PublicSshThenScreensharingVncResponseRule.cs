// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero builds/tests executed. workbook.R2054.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R902_PublicSshThenScreensharingVncResponseRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R902", Name: "Public SSH attempt then screensharingd VNC SYN-ACK", Category: "InitialAccess",
            Description: "Public TCP/22 SYN to a private host followed by locally attributed screensharingd TCP/5900 SYN-ACK back to the same public peer within 45s; no SSH or VNC authentication or linked user session is established.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R902.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R902", Name = "Public SSH attempt then screensharingd VNC SYN-ACK", Category = "InitialAccess",
            Description = "workbook.R2054: Public TCP/22 SYN to a private host followed by locally attributed screensharingd TCP/5900 SYN-ACK back to the same public peer within 45s; no SSH or VNC authentication or linked user session is established.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "tcp.flags", "packet.id", "process.id", "process.name" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Coherent typed IPv4 packet and specific process attribution where required.", "Ordered independent UTC observations where correlation applies." },
            NegativeConditions = new[] { "Missing or contradictory typed evidence, wrong endpoint, duplicate IDs, reverse UTC and expired correlation fail closed.",
                "No unsupported authentication, execution, file access, authorization or causality inferred." },
            FalsePositives = new[] { "Approved administration, diagnostics, maintenance and software deployment can match." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "public_ssh_syn_then_same_peer_screensharingd_vnc_synack",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory evidence",
                "duplicate IDs and reverse UTC", "correlation expiry and key isolation where applicable", "cooldown recovery",
                "raw Info exclusion", "neighbor independence", "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R902_PublicSshThenScreensharingVncResponseRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r) || r.Sni != null || r.HttpUri != null || r.DnsIsResponse) return NoMatch();
            var first = Research786NetworkEvidence.PublicPrivate(r) && Research676Evidence.Syn(r)
                && r.DestinationPort == 22;
            var second = Research786NetworkEvidence.PrivatePublic(r) && Research676Evidence.SynAck(r)
                && r.SourcePort == 5900 && Research676Evidence.Process(r, "screensharingd");
            if (!first && !second) return NoMatch();
            var key = first ? r.Destination! + "|" + r.Source! : r.Source! + "|" + r.Destination!;
            if (!_stages.Observe(key, r.Id, context.TimestampUtc, first, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2054", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "public_ssh_syn_then_same_peer_screensharingd_vnc_synack", "rule"),
                new DetectionEvidenceItem("outcome", "typed_network_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Public SSH attempt then screensharingd VNC SYN-ACK observed; authorization, causality and security outcome remain unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "source_specific_workbook_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 2, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
