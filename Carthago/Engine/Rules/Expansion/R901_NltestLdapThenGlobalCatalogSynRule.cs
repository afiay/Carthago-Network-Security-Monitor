// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero builds/tests executed. workbook.R1991.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R901_NltestLdapThenGlobalCatalogSynRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R901", Name: "Nltest private LDAP then Global Catalog SYN", Category: "Discovery",
            Description: "Same private source, nltest PID and private peer receive TCP/389 then TCP/3268 SYNs within 45s; LDAP queries, domain trust enumeration and authentication are not observed.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R901.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R901", Name = "Nltest private LDAP then Global Catalog SYN", Category = "Discovery",
            Description = "workbook.R1991: Same private source, nltest PID and private peer receive TCP/389 then TCP/3268 SYNs within 45s; LDAP queries, domain trust enumeration and authentication are not observed.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "destination.port", "tcp.flags", "packet.id", "process.id", "process.name" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Coherent typed IPv4 packet and specific process attribution where required.", "Ordered independent UTC observations where correlation applies." },
            NegativeConditions = new[] { "Missing or contradictory typed evidence, wrong endpoint, duplicate IDs, reverse UTC and expired correlation fail closed.",
                "No unsupported authentication, execution, file access, authorization or causality inferred." },
            FalsePositives = new[] { "Approved administration, diagnostics, maintenance and software deployment can match." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "nltest_private_ldap389_then_gc3268",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory evidence",
                "duplicate IDs and reverse UTC", "correlation expiry and key isolation where applicable", "cooldown recovery",
                "raw Info exclusion", "neighbor independence", "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R901_NltestLdapThenGlobalCatalogSynRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r) || !Research786NetworkEvidence.Internal(r)
                || !Research676Evidence.Process(r, "nltest.exe", "nltest") || !Research676Evidence.Syn(r)
                || r.Source == r.Destination || r.Sni != null || r.HttpUri != null || r.DnsIsResponse) return NoMatch();
            var first = r.DestinationPort == 389;
            if (!first && r.DestinationPort != 3268) return NoMatch();
            var key = r.Source! + "|" + r.Destination! + "|" + r.ProcessId;
            if (!_stages.Observe(key, r.Id, context.TimestampUtc, first, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1991", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "nltest_private_ldap389_then_gc3268", "rule"),
                new DetectionEvidenceItem("outcome", "typed_network_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Nltest private LDAP then Global Catalog SYN observed; authorization, causality and security outcome remain unverified.",
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
