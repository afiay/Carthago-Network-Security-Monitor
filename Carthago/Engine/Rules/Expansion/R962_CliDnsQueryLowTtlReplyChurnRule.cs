// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Original workbook R2843; xUnit source authored first.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R962_CliDnsQueryLowTtlReplyChurnRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R962", Name: "CLI DNS A query then three distinct low-TTL public answers", Category: "DnsThreat",
            Description: "Local curl/python-attributed complete UDP IN/A queries, each matched to a direct single-A low-TTL reply by wire transaction ID and reverse tuple, then three distinct public answers for the same querying PID, resolver and name within 45s. Legitimate CDN behavior and malicious fast flux are not distinguished.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R962.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R962", Name = "CLI DNS A query then three distinct low-TTL public answers", Category = "DnsThreat",
            Description = "workbook.R2843: Local curl/python-attributed complete UDP IN/A queries, each matched to a direct single-A low-TTL reply by wire transaction ID and reverse tuple, then three distinct public answers for the same querying PID, resolver and name within 45s. Legitimate CDN behavior and malicious fast flux are not distinguished.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Dns },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "process.id", "process.name", "dns.qname", "dns.qtype", "dns.rcode", "dns.ttl", "dns.answers", "dns.transaction.id", "dns.capture.validated" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Local curl/python-attributed complete UDP IN/A queries, each matched to a direct single-A low-TTL reply by wire transaction ID and reverse tuple, then three distinct public answers for the same querying PID, resolver and name within 45s. Legitimate CDN behavior and malicious fast flux are not distinguished.", "Coherent typed IPv4 fields and independent bounded UTC observations." },
            NegativeConditions = new[] { "Wrong endpoints, missing or contradictory typed evidence, duplicate IDs, reverse UTC or expired windows fail closed.",
                "No unsupported host action, authenticated session, authorization or security outcome inferred." },
            FalsePositives = new[] { "Authorized administration, maintenance, deployment and diagnostics may share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 6, Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "R962_CliDnsQueryLowTtlReplyChurnRule",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory fields", "duplicate and reverse UTC", "correlation expiry and isolation", "cooldown recovery", "raw Info excluded", "independent state and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly DnsQualifiedQueryWindow _queries = new();
        private readonly Research706DistinctWindow _distinct = new();
        public R962_CliDnsQueryLowTtlReplyChurnRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r) || !DnsQualifiedEvidence.Message(r)) return NoMatch();
            var first = Research786NetworkEvidence.PrivatePublic(r) && Research786NetworkEvidence.UdpData(r) && Research786NetworkEvidence.DnsQuestion(r) && Research676Evidence.Process(r, "curl", "curl.exe", "python", "python3", "python.exe") && r.DnsQtype == "A";
            var second = Research786NetworkEvidence.PublicPrivate(r) && Research786NetworkEvidence.UdpData(r) && r.SourcePort == 53 && r.ApplicationProtocol == "DNS" && r.DnsIsResponse && r.DnsQtype == "A" && r.DnsRcode == "NOERROR" && r.DnsValidatedSingleAAnswer && r.DnsAnswers == r.DnsValidatedAnswerAddress && r.DnsTtl == r.DnsValidatedAnswerTtl && r.DnsTtl is >= 1 and <= 30 && !string.IsNullOrWhiteSpace(r.DnsQname) && r.DnsQname.Length <= 253 && r.HttpMethod == null && r.HttpUri == null && r.TlsVersion == null && r.Sni == null && System.Net.IPAddress.TryParse(r.DnsAnswers, out var answer) && Research646Evidence.Public(answer);
            if (!first && !second) return NoMatch();
            var key = DnsQualifiedEvidence.Key(r, first);
            if (first)
            {
                _queries.Observe(key, r.Id, r.ProcessId, context.TimestampUtc);
                return NoMatch();
            }
            if (!_queries.TryConsume(key, r.Id, context.TimestampUtc, out int queryPid)) return NoMatch();
            if (!_distinct.Observe(r.Destination! + "|" + r.Source! + "|" + queryPid + "|" + r.DnsValidatedQuestionName!.ToLowerInvariant(), r.DnsValidatedAnswerAddress!, r.Id, context.TimestampUtc, 3, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2843", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "R962_CliDnsQueryLowTtlReplyChurnRule", "rule"),
                new DetectionEvidenceItem("outcome", "typed_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "CLI DNS A query then three distinct low-TTL public answers observed; authorization, causality and outcome remain unverified.", evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "capture_attested_dns_transaction");
                    confidence.AddEvidence(0.33, "specific_workbook_observable_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 6, windowSeconds: 45);
            evt = DnsSignatureRequestEvidence.RedactQuery(evt, r.DnsQname!);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
