// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero tests/builds executed. workbook.R2813.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R881_PublicFtpThenPrivateTftpRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R881", Name: "Public FTP control SYN then private parsed TFTP WRQ", Category: "LateralMovement",
            Description: "Public TCP/21 SYN to a private host precedes that host's capture-attested TFTP WRQ to another private device within 60s; file identity, actual transfer and file placement are unobserved.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R881.Enabled",
            EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R881", Name = "Public FTP control SYN then private parsed TFTP WRQ", Category = "LateralMovement",
            Description = "workbook.R2813: Public TCP/21 SYN to a private host precedes that host's capture-attested TFTP WRQ to another private device within 60s; file identity, actual transfer and file placement are unobserved.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "destination.port", "protocol", "tcp.flags", "packet.id", "tftp.request.opcode", "tftp.request.correlation" },
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
            DistinctBy = "public_ftp21_syn_then_same_private_host_udp69_to_private_peer",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near-miss cases",
                "missing or contradictory transport", "duplicate and reverse UTC / expired window",
                "cooldown recovery", "raw Info exclusion", "neighbor independence",
                "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R881_PublicFtpThenPrivateTftpRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            if (Research676Evidence.Syn(r) && Research786NetworkEvidence.PublicPrivate(r)
                && r.DestinationPort == 21 && r.HttpMethod == null && r.HttpUri == null
                && r.DnsQname == null && r.TlsVersion == null)
            {
                _stages.Observe(r.Destination!, r.Id, context.TimestampUtc, true, 60);
                return NoMatch();
            }
            if (!Research786NetworkEvidence.Internal(r) || r.Source == r.Destination
                || !TftpQualifiedEvidence.Request(r) || r.TftpInitialRequestOpcode != 2
                || !_stages.Observe(r.Source!, r.Id, context.TimestampUtc, false, 60))
                return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2813", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "public_ftp21_syn_then_same_private_host_udp69_to_private_peer", "rule"),
                new DetectionEvidenceItem("outcome", "parsed_tftp_write_request_only_causality_authorization_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Public FTP control SYN then private parsed TFTP WRQ; producer provenance, authorization, causality and outcome unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "capture_attested_tftp_write_request");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 2, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

