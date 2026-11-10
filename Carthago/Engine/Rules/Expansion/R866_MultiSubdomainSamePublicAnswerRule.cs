// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero tests/builds executed. workbook.R1007.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R866_MultiSubdomainSamePublicAnswerRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R866", Name: "Distinct subdomain DNS A replies share one public address", Category: "DnsThreat",
            Description: "Three distinct internal-client DNS A response names under one base domain resolve to the same public IPv4 within 60s; zone updates and wildcard configuration are not observable.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R866.Enabled",
            EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R866", Name = "Distinct subdomain DNS A replies share one public address", Category = "DnsThreat",
            Description = "workbook.R1007: Three distinct internal-client DNS A response names under one base domain resolve to the same public IPv4 within 60s; zone updates and wildcard configuration are not observable.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Dns },
            RequiredFields = new[] { "dns.qname", "dns.answers", "source", "destination", "packet.id" },
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
            MinimumConfidence = 80, WindowThreshold = 3,
            Window = TimeSpan.FromSeconds(60), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "distinct_subdomains_same_public_a_reply",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive and benign typed cases", "missing and contradictory fields",
                "duplicate IDs, reverse time, window expiry", "cooldown recovery",
                "raw Info exclusion", "neighbor independence", "Candidate Shadow registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research706DistinctWindow _distinct = new();
        public R866_MultiSubdomainSamePublicAnswerRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.UdpData(r) || !Research786NetworkEvidence.Internal(r)
                || r.SourcePort != 53 || !r.DnsIsResponse
                || !string.Equals(r.ApplicationProtocol, "DNS", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(r.DnsQtype, "A", StringComparison.OrdinalIgnoreCase)
                || string.IsNullOrWhiteSpace(r.DnsQname) || r.DnsQname.Length > 253
                || r.DnsTtl is < 1 or > 86400
                || r.HttpMethod != null || r.HttpUri != null || r.TlsVersion != null || r.Sni != null
                || !IPAddress.TryParse(r.DnsAnswers, out var answer) || !Research646Evidence.Public(answer))
                return NoMatch();
            var labels = r.DnsQname.TrimEnd('.').ToLowerInvariant().Split('.');
            if (labels.Length < 3 || Array.Exists(labels, label => label.Length is < 1 or > 63)) return NoMatch();
            var baseDomain = labels[labels.Length - 2] + "." + labels[labels.Length - 1];
            var key = r.Source! + "|" + r.Destination! + "|" + baseDomain + "|" + answer;
            if (!_distinct.Observe(key, r.DnsQname.TrimEnd('.').ToLowerInvariant(), r.Id, context.TimestampUtc, 3, 60))
                return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1007", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "distinct_subdomains_same_public_a_reply", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_shape_only_causality_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Distinct subdomain DNS A replies share one public address; producer provenance, authorization and security outcome unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 3, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

