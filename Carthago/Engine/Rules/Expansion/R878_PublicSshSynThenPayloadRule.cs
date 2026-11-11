// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero tests/builds executed. workbook.R2698.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R878_PublicSshSynThenPayloadRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R878", Name: "Public SSH SYN followed by same-flow payload", Category: "InitialAccess",
            Description: "Public TCP/22 SYN to a private host is followed by application-sized data from the same public client and source port within 40s; Linux identity, SSH authentication, authorization and OT asset role are unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R878.Enabled",
            EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R878", Name = "Public SSH SYN followed by same-flow payload", Category = "InitialAccess",
            Description = "workbook.R2698: Public TCP/22 SYN to a private host is followed by application-sized data from the same public client and source port within 40s; Linux identity, SSH authentication, authorization and OT asset role are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "source.port", "tcp.flags", "packet.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Coherent typed IPv4 transport fields and independent observable source predicate.",
                "Bounded per-rule monotonic UTC observation, with no unavailable producer asserted."
            },
            NegativeConditions = new[]
            {
                "Missing, contradictory, duplicate, out-of-order or expired evidence fails closed.",
                "No authenticated identity, file transfer, decoded encrypted content, command execution, configuration or outcome inferred."
            },
            FalsePositives = new[]
            {
                "Approved maintenance, software deployment, diagnostics, administrative sessions and normal traffic may share this shape."
            },
            MinimumConfidence = 80, WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(40), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "public_private_ssh22_syn_then_same_source_port_payload",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near-miss cases",
                "missing or contradictory transport", "duplicate and reverse UTC / expired window",
                "cooldown recovery", "raw Info exclusion", "neighbor independence",
                "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R878_PublicSshSynThenPayloadRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r) || !Research786NetworkEvidence.PublicPrivate(r)
                || r.DestinationPort != 22 || r.HttpMethod != null || r.HttpUri != null
                || r.DnsQname != null || r.Sni != null || r.TlsVersion != null)
                return NoMatch();
            var key = r.Source! + "|" + r.Destination! + "|" + r.SourcePort;
            if (Research676Evidence.Syn(r))
            { _stages.Observe(key, r.Id, context.TimestampUtc, true, 40); return NoMatch(); }
            if (!Research786NetworkEvidence.TcpData(r) || r.L4Len is < 128 or > 2048
                || !_stages.Observe(key, r.Id, context.TimestampUtc, false, 40))
                return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2698", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "public_private_ssh22_syn_then_same_source_port_payload", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_shape_only_causality_authorization_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Public SSH SYN followed by same-flow payload; producer provenance, authorization, causality and outcome unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 2, windowSeconds: 40);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

