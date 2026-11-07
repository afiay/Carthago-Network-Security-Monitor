// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R2855.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R766_OsascriptHighEntropyDnsQueryBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R766",
            Name: "osascript high-entropy DNS query burst",
            Category: "Dns",
            Description: "osascript is associated with three high-entropy DNS queries to a public resolver for the same root domain within two minutes. AppleScript origin, encoded content, authoritative-server control, data exfiltration and command-and-control are not established.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R766.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R766",
            Name = "osascript high-entropy DNS query burst",
            Category = "Dns",
            Description = "workbook.R2855: the workbook analytic describes macOS scripting environments performing encoded-subdomain DNS. Carthago narrows this to exact osascript attribution plus repeated high-entropy public-resolver queries.",
            Severity = SeverityLevel.Medium,
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
            FalsePositives = new[] { "AppleScript automation, DNS diagnostics and vendor workflows can legitimately generate unusual DNS labels." },
            MinimumConfidence = 82,
            WindowThreshold = 3,
            Window = TimeSpan.FromSeconds(120),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+osascript_pid+root_domain+high_entropy_dns_burst",
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

        public R766_OsascriptHighEntropyDnsQueryBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research766Evidence.MacDnsProcess(r)
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
                new DetectionEvidenceItem("research.identifier", "workbook.R2855", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "osascript_high_entropy_public_dns_queries", "rule"),
                new DetectionEvidenceItem("outcome", "tool_attributed_dns_burst_only_tunneling_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "osascript high-entropy DNS query burst observed; encoded content, tunnel direction and command-and-control outcome are unknown.",
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
