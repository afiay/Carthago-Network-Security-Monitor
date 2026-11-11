// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero tests/builds executed. workbook.R2694.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R885_PublicCgiPostThenBashTlsRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R885", Name: "Public CGI POST then same host bash-attributed public TLS", Category: "InitialAccess",
            Description: "Public POST to a private CGI diagnostic path precedes bash-attributed public TLS/8443 to a different IP from that host within 60s; no process spawn, command execution, exploitation or causality proven.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R885.Enabled",
            EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R885", Name = "Public CGI POST then same host bash-attributed public TLS", Category = "InitialAccess",
            Description = "workbook.R2694: Public POST to a private CGI diagnostic path precedes bash-attributed public TLS/8443 to a different IP from that host within 60s; no process spawn, command execution, exploitation or causality proven.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Http, RuleTelemetryKind.Tls },
            RequiredFields = new[] { "http.method", "http.uri", "source", "destination", "process.id", "tls.sni", "packet.id" },
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
            DistinctBy = "public_cgi_diag_post_then_bash_tls_other_public_peer",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near-miss cases",
                "missing or contradictory transport", "duplicate and reverse UTC / expired window",
                "cooldown recovery", "raw Info exclusion", "neighbor independence",
                "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research806DifferentPeerWindow _different = new();
        public R885_PublicCgiPostThenBashTlsRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r)) return NoMatch();
            if (Research786NetworkEvidence.PublicPrivate(r) && r.DestinationPort == 80
                && WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                && method == "POST" && uri == "/cgi-bin/diag.cgi"
                && !string.IsNullOrWhiteSpace(r.HttpHost) && r.HttpHost.Length <= 253)
            {
                _different.Observe(r.Destination!, r.Source!, r.Id, context.TimestampUtc, true);
                return NoMatch();
            }
            if (!Research786NetworkEvidence.PrivatePublic(r) || r.DestinationPort != 8443
                || !Research676Evidence.Process(r, "bash")
                || r.L4Len is < 500 or > 1200 || string.IsNullOrWhiteSpace(r.TlsVersion)
                || string.IsNullOrWhiteSpace(r.Sni) || r.Sni.Length > 253
                || r.HttpMethod != null || r.HttpUri != null || r.DnsQname != null
                || !_different.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc, false))
                return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2694", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "public_cgi_diag_post_then_bash_tls_other_public_peer", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_shape_only_causality_authorization_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Public CGI POST then same host bash-attributed public TLS; producer provenance, authorization, causality and outcome unverified.",
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

