// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Test source authored first; no build/test execution. workbook.R2055.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R916_HostdPublicDnsQueryNxdomainReplyRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R916", Name: "Hostd public DNS query then reverse-tuple NXDOMAIN", Category: "DnsAdvanced",
            Description: "Hostd/vpxa capture-attested UDP IN/A query to a public resolver followed by a validated no-answer NXDOMAIN with matching transaction ID, normalized question and reverse tuple. DGA, resolver trust and attack outcome remain unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R916.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R916", Name = "Hostd public DNS query then reverse-tuple NXDOMAIN", Category = "DnsAdvanced",
            Description = "workbook.R2055: Hostd/vpxa capture-attested UDP IN/A query to a public resolver followed by a validated no-answer NXDOMAIN with matching transaction ID, normalized question and reverse tuple. DGA, resolver trust and attack outcome remain unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Dns },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "process.id", "process.name", "dns.qname", "dns.qtype", "dns.rcode", "dns.transaction.id", "dns.capture.validated" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Hostd/vpxa capture-attested UDP IN/A query to a public resolver followed by a validated no-answer NXDOMAIN with matching transaction ID, normalized question and reverse tuple. DGA, resolver trust and attack outcome remain unknown.", "Coherent typed IPv4 fields and bounded UTC observations." },
            NegativeConditions = new[] { "Missing or contradictory evidence, mismatched keys, duplicate packet IDs, reverse UTC and expired windows fail closed.",
                "No unsupported host identity, execution, authentication, authorization or security outcome inferred." },
            FalsePositives = new[] { "Authorized administration, diagnostics, software deployment, maintenance and security testing can share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "R916_HostdPublicDnsQueryNxdomainReplyRule",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory fields", "duplicate and reverse UTC",
                "correlation expiry and key isolation", "cooldown recovery", "raw Info exclusion", "neighbor independence", "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R916_HostdPublicDnsQueryNxdomainReplyRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r) || !DnsQualifiedEvidence.Message(r)) return NoMatch();
            var first = Research786NetworkEvidence.PrivatePublic(r) && r.DestinationPort == 53 && Research676Evidence.Process(r, "hostd", "vpxa") && Research786NetworkEvidence.UdpData(r) && Research786NetworkEvidence.DnsQuestion(r) && r.DnsQtype == "A";
            var second = Research786NetworkEvidence.PublicPrivate(r) && r.SourcePort == 53 && Research786NetworkEvidence.UdpData(r) && r.ApplicationProtocol == "DNS" && r.DnsIsResponse && r.DnsQtype == "A" && r.DnsRcode == "NXDOMAIN" && r.DnsValidatedNxdomain && !string.IsNullOrWhiteSpace(r.DnsQname) && r.DnsQname.Length <= 253 && string.IsNullOrWhiteSpace(r.DnsAnswers) && r.HttpMethod == null && r.HttpUri == null && r.TlsVersion == null && r.Sni == null;
            if (!first && !second) return NoMatch();
            var key = DnsQualifiedEvidence.Key(r, first);
            if (!_stages.Observe(key, r.Id, context.TimestampUtc, first, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2055", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "R916_HostdPublicDnsQueryNxdomainReplyRule", "rule"),
                new DetectionEvidenceItem("outcome", "typed_network_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Hostd public DNS query then reverse-tuple NXDOMAIN observed; authorization, causality and outcome remain unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "capture_attested_dns_transaction");
                    confidence.AddEvidence(0.33, "specific_workbook_observable_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 2, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
