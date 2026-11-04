// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R1768.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R751_MacProcessCodeRepositoryTlsPayloadBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R751",
            Name: "macOS-characteristic process code-repository TLS payload burst",
            Category: "CloudDev",
            Description: "osascript, curl, git, Microsoft Word, or Microsoft Excel is associated with four substantial TLS/443 payload observations to GitHub, GitLab, or Bitbucket within two minutes. Repository API method, authentication, git operation, local file source and exfiltration are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R751.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R751",
            Name = "macOS-characteristic process code-repository TLS payload burst",
            Category = "CloudDev",
            Description = "workbook.R1768: the source analytic correlates macOS file access with code-repository upload. Carthago cannot decrypt HTTPS or see local file reads, so this candidate requires only process attribution, repository SNI and a bounded payload burst.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Tls, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "tls.sni", "tls.version", "process.name", "process.id", "l4.length" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed packet/parser fields plus the exact best-effort local process/network predicate for this candidate.",
                "Stateful predicates require unique packet IDs, monotonic UTC observations and bounded rule-owned state.",
                "Only the observed connection, request, packet burst, service host or two-stage network sequence is asserted."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, malformed endpoints and free-form Info-only assertions.",
                "Reject duplicate packet IDs, reverse time, expired windows and cooldown repeats.",
                "Do not infer file reads, encryption execution, command-line arguments, upload completion, authentication, exploit success, C2, lateral compromise or data loss."
            },
            FalsePositives = new[] { "Developer activity, CI/CD, repository synchronization, release engineering and documentation workflows can legitimately produce repository TLS bursts." },
            MinimumConfidence = 81,
            WindowThreshold = 4,
            Window = TimeSpan.FromSeconds(120),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+mac_process+code_repository_sni+payload_burst",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive real-life-shaped sample and rule-specific benign near miss",
                "missing and contradictory producer fields",
                "duplicate IDs, reverse time and expiry for correlated candidates",
                "cooldown suppression and recovery",
                "evidence privacy, non-convergence, Candidate Shadow and registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research666TimedWindow _timed = new();

        public R751_MacProcessCodeRepositoryTlsPayloadBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research746Evidence.Tls443(r)
                || !Research746Evidence.MacRepositoryProcess(r)
                || !Research746Evidence.CodeRepositoryHost(r.Sni)
                || r.L4Len is null or < 900 or > 8192
                || !_timed.Observe(r.Source + "|" + r.Sni + "|" + r.ProcessId,
                    r.Id, r.L4Len.Value, context.TimestampUtc, 4, false, 5000))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1768", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "mac_process_code_repository_tls_payload_burst", "rule"),
                new DetectionEvidenceItem("outcome", "repository_tls_burst_only_operation_and_exfiltration_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "macOS-characteristic process code-repository TLS payload burst observed; repository operation, authentication, file source and exfiltration are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 4,
                windowSeconds: 120);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
