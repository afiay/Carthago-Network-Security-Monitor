// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R2774.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R767_WindowsScriptHighEntropyDnsQueryBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R767",
            Name: "Windows script/LOLBIN high-entropy DNS query burst",
            Category: "Dns",
            Description: "PowerShell, rundll32, or Windows Python is associated with three high-entropy DNS queries to a public resolver for the same root domain within two minutes. Command line, encoded payload meaning, authoritative-server ownership and DNS-tunneling success are not observed.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R767.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R767",
            Name = "Windows script/LOLBIN high-entropy DNS query burst",
            Category = "Dns",
            Description = "workbook.R2774: the workbook analytic describes anomalous DNS from PowerShell, rundll32 and Python. This candidate independently requires exact Windows process basenames and repeated high-entropy queries.",
            Severity = SeverityLevel.High,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Dns, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "dns.qname", "dns.qtype", "process.name", "process.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed packet/parser fields and this rule's exact independent predicate.",
                "Process attribution is best-effort local tuple enrichment, not authenticated endpoint process identity.",
                "Stateful candidates accept unique packet IDs in monotonic UTC order inside bounded rule-owned windows."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, malformed endpoints and free-form Info-only assertions.",
                "Reject duplicate packet IDs, reverse time, expired windows and cooldown repeats.",
                "Do not infer command lines, approved asset role, credentials, authentication success, C2 control, transfer completion, DoS impact or compromise."
            },
            FalsePositives = new[] { "Administrative automation, DNS diagnostics, software deployment and security testing can generate high-entropy queries from scripting processes." },
            MinimumConfidence = 86,
            WindowThreshold = 3,
            Window = TimeSpan.FromSeconds(120),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+windows_script_pid+root_domain+high_entropy_dns_burst",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive shaped case and benign near miss",
                "missing/contradictory telemetry",
                "duplicate ID, reverse-time and expiry for stateful candidates",
                "cooldown suppression and recovery",
                "privacy/redaction, non-convergence, Candidate Shadow and registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research736CountWindow _window = new();

        public R767_WindowsScriptHighEntropyDnsQueryBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research766Evidence.WindowsDnsProcess(r)
                || !Research766Evidence.HighEntropyPublicDns(r, out var query, out var root)
                || !_window.Observe(r.Source + "|" + root + "|" + r.ProcessId,
                    r.Id, query.Length, context.TimestampUtc, 3, 120))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2774", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "windows_script_high_entropy_public_dns_queries", "rule"),
                new DetectionEvidenceItem("outcome", "process_attributed_dns_burst_only_tunneling_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.High,
                "Windows script/LOLBIN high-entropy DNS query burst observed; encoded content, authoritative-server control and tunneling outcome are unknown.",
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
