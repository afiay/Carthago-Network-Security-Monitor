// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R2743.
using System;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R764_LinuxDnsTunnelToolQueryBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R764",
            Name: "Linux DNS-tunneling tool high-entropy query burst",
            Category: "Dns",
            Description: "iodine, iodined, dnscat2, dnscat2-client, or dig is associated with three high-entropy DNS queries to a public resolver for the same root domain within two minutes. Cron/reverse-shell ancestry, encoded content, authoritative-server control and tunneling success are not observed.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R764.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R764",
            Name = "Linux DNS-tunneling tool high-entropy query burst",
            Category = "Dns",
            Description = "workbook.R2743: the source analytic correlates Linux process execution with long/frequent DNS subdomains. R102 is process-agnostic long-label analysis; this candidate independently requires exact DNS-oriented tool attribution.",
            Severity = SeverityLevel.High,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Dns, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "dns.qname", "dns.qtype", "process.name", "process.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed producer fields and this independent rule-specific predicate.",
                "Process identity, where used, is best-effort local tuple enrichment rather than authenticated endpoint identity.",
                "Stateful rules accept unique packet IDs in monotonic UTC order inside bounded rule-owned windows."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, malformed endpoints and Info-only assertions.",
                "Reject duplicate packet IDs, reverse time, expired sequences and cooldown repeats.",
                "Do not infer file access, credentials, command-line arguments, successful authentication, exploit success, C2 control, transfer completion or compromise."
            },
            FalsePositives = new[] { "DNS diagnostics, penetration testing, lab tunneling exercises and specialized network troubleshooting can legitimately use dig, iodine or dnscat-like tooling." },
            MinimumConfidence = 86,
            WindowThreshold = 3,
            Window = TimeSpan.FromSeconds(120),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+dns_tunnel_tool+root_domain+high_entropy_burst",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive shaped sample and rule-specific benign near miss",
                "missing and contradictory telemetry",
                "duplicate ID, reverse-time and expiry where stateful",
                "cooldown suppression and recovery",
                "privacy, non-convergence, Candidate Shadow and registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research736CountWindow _window = new();

        public R764_LinuxDnsTunnelToolQueryBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research756Evidence.LinuxDnsTunnelTool(r)
                || !Research756Evidence.HighEntropyPublicDns(r, out var query, out var root)
                || !_window.Observe(r.Source + "|" + root + "|" + r.ProcessId,
                    r.Id, query.Length, context.TimestampUtc, 3, 120))
                return NoMatch();

            var cool = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (cool == WebSignatureObservation.None) return NoMatch();
            if (cool == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2743", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "linux_dns_tunnel_tool_high_entropy_public_queries", "rule"),
                new DetectionEvidenceItem("outcome", "tool_attributed_dns_burst_only_tunneling_outcome_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.High,
                "DNS-tunneling-tool high-entropy query burst observed; encoded content, server control and tunneling outcome are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 3,
                windowSeconds: 120);
            evt = DnsSignatureRequestEvidence.RedactQuery(evt, query);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
