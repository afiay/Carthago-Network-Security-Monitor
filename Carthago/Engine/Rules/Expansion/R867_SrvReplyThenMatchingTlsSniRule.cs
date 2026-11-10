// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero tests/builds executed. workbook.R1008.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R867_SrvReplyThenMatchingTlsSniRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R867", Name: "DNS SRV answer followed by matching public TLS SNI", Category: "DnsThreat",
            Description: "A private DNS SRV reply advertises a hostname, followed by the recipient's TLS connection bearing that SNI within 90s; DNS dynamic update or authentication is not observable.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R867.Enabled",
            EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R867", Name = "DNS SRV answer followed by matching public TLS SNI", Category = "DnsThreat",
            Description = "workbook.R1008: A private DNS SRV reply advertises a hostname, followed by the recipient's TLS connection bearing that SNI within 90s; DNS dynamic update or authentication is not observable.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Dns, RuleTelemetryKind.Tls },
            RequiredFields = new[] { "dns.qname", "dns.answers", "tls.sni", "source", "destination", "packet.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Coherent typed IPv4 transport fields and independent packet-observable predicate.",
                "Per-rule bounded monotonic UTC correlation; no missing producer claimed."
            },
            NegativeConditions = new[]
            {
                "Missing or contradictory fields, duplicate IDs, reversed time and expired windows fail closed.",
                "No trusted identity, host audit, changed configuration, authenticated action, exploit, C2 or impact inferred."
            },
            FalsePositives = new[]
            {
                "Authorized network administration, service discovery, maintenance and diagnostics may generate this shape."
            },
            MinimumConfidence = 80, WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(90), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "srv_response_then_matching_public_tls_sni",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive and benign typed cases", "missing and contradictory fields",
                "duplicate IDs, reverse time, window expiry", "cooldown recovery",
                "raw Info exclusion", "neighbor independence", "Candidate Shadow registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R867_SrvReplyThenMatchingTlsSniRule() : base(Rule, Profile) { }

        private static bool ValidHost(string? host)
        {
            if (string.IsNullOrWhiteSpace(host) || host.Length > 253
                || host.Contains(' ') || host.Contains('/') || !host.Contains('.')) return false;
            var labels = host.TrimEnd('.').Split('.');
            return labels.Length >= 2 && Array.TrueForAll(labels, label => label.Length is >= 1 and <= 63
                && Array.TrueForAll(label.ToCharArray(), c => char.IsLetterOrDigit(c) || c == '-' || c == '_'));
        }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (Research786NetworkEvidence.UdpData(r) && Research786NetworkEvidence.Internal(r)
                && r.SourcePort == 53 && r.DnsIsResponse
                && string.Equals(r.ApplicationProtocol, "DNS", StringComparison.OrdinalIgnoreCase)
                && string.Equals(r.DnsQtype, "SRV", StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(r.DnsQname) && r.DnsQname.Length <= 253
                && r.DnsQname.StartsWith("_", StringComparison.Ordinal)
                && r.DnsQname.Contains("._tcp.", StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(r.DnsAnswers) && ValidHost(r.DnsAnswers)
                && r.HttpMethod == null && r.HttpUri == null && r.Sni == null && r.TlsVersion == null)
            {
                _stages.Observe(r.Destination! + "|" + r.DnsAnswers.TrimEnd('.').ToLowerInvariant(),
                    r.Id, context.TimestampUtc, true, 90);
                return NoMatch();
            }
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || r.DestinationPort != 443 || string.IsNullOrWhiteSpace(r.TlsVersion)
                || !ValidHost(r.Sni) || r.HttpMethod != null || r.HttpUri != null
                || r.DnsQname != null || r.DnsIsResponse
                || !_stages.Observe(r.Source! + "|" + r.Sni!.TrimEnd('.').ToLowerInvariant(),
                    r.Id, context.TimestampUtc, false, 90)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1008", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "srv_response_then_matching_public_tls_sni", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_shape_only_causality_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "DNS SRV answer followed by matching public TLS SNI; producer provenance, authorization and security outcome unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 2, windowSeconds: 90);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

