// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R1724.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R752_MsiexecRemoteMsiHttpGetRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R752",
            Name: "msiexec cleartext HTTP retrieval of remote installer package",
            Category: "Execution",
            Description: "msiexec is associated with an outbound cleartext HTTP GET whose path ends in .msi, .msp, or .mst. Command-line arguments, package signature, download completion, installation, DLL execution and compromise are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R752.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R752",
            Name = "msiexec cleartext HTTP retrieval of remote installer package",
            Category = "Execution",
            Description = "workbook.R1724: the source analytic detects msiexec abuse involving remote installer packages, UNC/HTTP(S) paths or DLLs. Carthago lacks command-line and module-load telemetry, so this candidate is limited to exact msiexec attribution plus a parser-backed remote installer GET.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "http.method", "http.uri", "process.name", "process.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed packet/parser fields plus the exact best-effort local process/network predicate for this candidate.",
                "Only the observed remote installer request is asserted.",
                "No command-line, file-write, package-signature or execution outcome is inferred."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, malformed endpoints and free-form Info-only assertions.",
                "Reject non-msiexec processes, non-installer paths, duplicate IDs, reverse time and cooldown repeats.",
                "Do not infer download completion, installation, DLL execution or compromise."
            },
            FalsePositives = new[] { "Software deployment, enterprise repair, package management and approved remote installation workflows may legitimately retrieve MSI/MSP/MST packages with msiexec." },
            MinimumConfidence = 84,
            WindowThreshold = 1,
            Window = TimeSpan.FromSeconds(300),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+msiexec+remote_installer_http_path",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive remote MSI GET and benign non-installer GET",
                "missing and contradictory producer fields",
                "duplicate ID and reverse-time replay",
                "cooldown suppression and recovery",
                "evidence privacy, Candidate Shadow and registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();

        public R752_MsiexecRemoteMsiHttpGetRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research746Evidence.RemoteMsiHttpGet(r))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1724", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "msiexec_remote_installer_http_get", "rule"),
                new DetectionEvidenceItem("outcome", "installer_get_request_only_installation_and_execution_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "msiexec remote installer HTTP GET observed; command line, signature, download completion, installation and execution outcome are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 1,
                windowSeconds: 300);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
