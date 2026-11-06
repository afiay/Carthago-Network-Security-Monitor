// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R2669.
using System;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R763_EsxiStyleDnsTunnelShapeRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R763",
            Name: "ESXi-style DNS tool high-entropy query burst",
            Category: "Dns",
            Description: "busybox or nslookup is associated with three high-entropy DNS queries to a public resolver for the same root domain within two minutes. ESXi asset identity, shell script origin, malicious VIB presence, encoded payload meaning and DNS tunneling success are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R763.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R763",
            Name = "ESXi-style DNS tool high-entropy query burst",
            Category = "Dns",
            Description = "workbook.R2669: the source analytic targets unusual DNS from ESXi shell/custom-daemon contexts. Carthago cannot prove host role from packets alone, so this candidate is deliberately limited to ESXi-style shell/tool process attribution plus repeated high-entropy public-resolver queries.",
            Severity = SeverityLevel.Medium,
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
            FalsePositives = new[] { "Diagnostics, vendor scripts, DNS testing and encoded verification workflows can produce high-entropy DNS queries from BusyBox or nslookup." },
            MinimumConfidence = 82,
            WindowThreshold = 3,
            Window = TimeSpan.FromSeconds(120),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+esxi_style_dns_tool+root_domain+high_entropy_burst",
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

        public R763_EsxiStyleDnsTunnelShapeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research756Evidence.EsxiDnsTool(r)
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
                new DetectionEvidenceItem("research.identifier", "workbook.R2669", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "esxi_style_dns_tool_high_entropy_public_queries", "rule"),
                new DetectionEvidenceItem("outcome", "high_entropy_dns_burst_only_tunneling_and_host_role_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "ESXi-style DNS tool high-entropy query burst observed; host role, encoded content and tunneling outcome are unknown.",
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
