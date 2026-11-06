// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R1158.
using System;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R756_EsxiManagementProcessCodeRepositoryTlsBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R756",
            Name: "ESXi management-process code-repository TLS payload burst",
            Category: "CloudDev",
            Description: "hostd, vpxa, or vmx is associated with four substantial TLS/443 payload observations to GitHub, GitLab, or Bitbucket within two minutes. Datastore reads, HTTPS method, authentication, repository operation, unique TCP bytes and exfiltration are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R756.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R756",
            Name = "ESXi management-process code-repository TLS payload burst",
            Category = "CloudDev",
            Description = "workbook.R1158: the source analytic correlates datastore access with repository egress. Carthago retains only hypervisor-management process attribution, repository SNI and a bounded TLS payload burst.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Tls, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "tls.sni", "tls.version", "process.name", "process.id", "l4.length" },
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
            FalsePositives = new[] { "VMware support, repository-backed automation, infrastructure-as-code, backup and administrator tooling can legitimately contact code repositories." },
            MinimumConfidence = 82,
            WindowThreshold = 4,
            Window = TimeSpan.FromSeconds(120),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+esxi_process+repository_sni+payload_burst",
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
        private readonly Research666TimedWindow _timed = new();

        public R756_EsxiManagementProcessCodeRepositoryTlsBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research756Evidence.EsxiRepositoryTls(r)
                || r.L4Len is null or < 900 or > 8192
                || !_timed.Observe(r.Source + "|" + r.Sni + "|" + r.ProcessId,
                    r.Id, r.L4Len.Value, context.TimestampUtc, 4, false, 5000))
                return NoMatch();

            var cool = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (cool == WebSignatureObservation.None) return NoMatch();
            if (cool == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1158", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "esxi_management_process_repository_tls_payload_burst", "rule"),
                new DetectionEvidenceItem("outcome", "repository_tls_burst_only_operation_and_exfiltration_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "ESXi management-process repository TLS payload burst observed; datastore source, repository operation, unique bytes and exfiltration are unknown.",
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
