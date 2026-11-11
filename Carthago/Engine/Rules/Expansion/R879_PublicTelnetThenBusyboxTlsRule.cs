// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero tests/builds executed. workbook.R2804.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R879_PublicTelnetThenBusyboxTlsRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R879", Name: "Public Telnet SYN then busybox-attributed public TLS", Category: "LateralMovement",
            Description: "Public TCP/23 SYN to private host precedes busybox-attributed TLS/8443 egress from that host within 60s; Telnet login, shell execution, process causality and device role are not established.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R879.Enabled",
            EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R879", Name = "Public Telnet SYN then busybox-attributed public TLS", Category = "LateralMovement",
            Description = "workbook.R2804: Public TCP/23 SYN to private host precedes busybox-attributed TLS/8443 egress from that host within 60s; Telnet login, shell execution, process causality and device role are not established.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Tls },
            RequiredFields = new[] { "source", "destination", "destination.port", "process.id", "tls.sni", "packet.id" },
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
            Window = TimeSpan.FromSeconds(60), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "public_telnet23_syn_then_same_host_busybox_public_tls8443",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near-miss cases",
                "missing or contradictory transport", "duplicate and reverse UTC / expired window",
                "cooldown recovery", "raw Info exclusion", "neighbor independence",
                "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R879_PublicTelnetThenBusyboxTlsRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            if (Research676Evidence.Syn(r) && Research786NetworkEvidence.PublicPrivate(r)
                && r.DestinationPort == 23)
            {
                _stages.Observe(r.Destination!, r.Id, context.TimestampUtc, true, 60);
                return NoMatch();
            }
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || r.DestinationPort != 8443 || r.L4Len is < 500 or > 1200
                || !Research676Evidence.Process(r, "busybox", "busybox.exe")
                || string.IsNullOrWhiteSpace(r.TlsVersion)
                || string.IsNullOrWhiteSpace(r.Sni) || r.Sni.Length > 253
                || r.HttpMethod != null || r.HttpUri != null || r.DnsQname != null
                || !_stages.Observe(r.Source!, r.Id, context.TimestampUtc, false, 60))
                return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2804", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "public_telnet23_syn_then_same_host_busybox_public_tls8443", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_shape_only_causality_authorization_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Public Telnet SYN then busybox-attributed public TLS; producer provenance, authorization, causality and outcome unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 2, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

