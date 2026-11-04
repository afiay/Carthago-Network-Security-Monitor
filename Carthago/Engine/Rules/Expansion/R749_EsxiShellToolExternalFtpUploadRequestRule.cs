// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R1215.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R749_EsxiShellToolExternalFtpUploadRequestRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R749",
            Name: "ESXi-style shell tool external FTP upload request",
            Category: "ExfiltrationAdvanced",
            Description: "busybox, curl, wget, ftpput, or lftp is associated with a parsed FTP STOR/APPE upload command to a public endpoint. Shell history, source file, server response, data-channel delivery and exfiltration are not observed.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R749.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R749",
            Name = "ESXi-style shell tool external FTP upload request",
            Category = "ExfiltrationAdvanced",
            Description = "workbook.R1215: the source analytic describes ESXi configuration/snapshot transfer via unencrypted FTP/HTTP. This candidate is deliberately limited to an ESXi-style shell/transfer-tool process and a parser-backed external FTP upload command.",
            Severity = SeverityLevel.High,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Payload, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "ftp.operation", "process.name", "process.id" },
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
            FalsePositives = new[] { "Legacy administration, firmware staging, backup, migration and support workflows can legitimately use FTP upload commands." },
            MinimumConfidence = 84,
            WindowThreshold = 1,
            Window = TimeSpan.FromSeconds(300),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+esxi_style_shell_process+external_ftp_upload_request",
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

        public R749_EsxiShellToolExternalFtpUploadRequestRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch246250Evidence.FtpUpload(r)
                || !Research746Evidence.PrivateToPublic(r)
                || !Research746Evidence.EsxiFtpProcess(r)
                || r.HttpMethod != null || r.DnsQname != null || r.IsQuic || r.TlsVersion != null)
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1215", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "esxi_style_shell_process_external_ftp_upload_request", "rule"),
                new DetectionEvidenceItem("outcome", "ftp_upload_command_only_data_channel_and_exfiltration_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.High,
                "ESXi-style shell/transfer-tool external FTP upload request observed; source file, server response, data-channel delivery and exfiltration are unknown.",
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
