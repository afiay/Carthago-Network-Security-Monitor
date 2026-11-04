// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R1510.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R736_LinuxNonBrowserTlsPayloadBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R736",
            Name: "Linux non-browser process external TLS payload burst",
            Category: "ExfiltrationAdvanced",
            Description: "curl, wget, Python, rsync, scp, sftp, or rclone is associated with four substantial TLS/443 payload observations to one public peer within two minutes. File reads, archive creation, unique TCP bytes, upload semantics and exfiltration are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R736.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R736",
            Name = "Linux non-browser process external TLS payload burst",
            Category = "ExfiltrationAdvanced",
            Description = "workbook.R1510: the source analytic correlates staged file access with encrypted outbound transfer. Carthago retains only exact transfer-tool process attribution plus a bounded TLS payload burst.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Tls, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "tls.sni", "tls.version", "process.name", "process.id", "l4.length" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed packet/parser fields and the exact local process/network predicate for this independent candidate.",
                "Correlated rules require unique packet IDs, monotonic UTC ordering and bounded rule-owned state.",
                "Only the observable request, TLS contact, connection attempt, packet burst or cadence is asserted."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, malformed endpoints and free-form Info-only evidence.",
                "Reject duplicate packet IDs, reverse time, expired windows and cooldown repeats.",
                "Do not infer file reads, command-line arguments, cron execution, upload completion, C2 control, proxy establishment, encoded content, DoS impact or compromise."
            },
            FalsePositives = new[] { "Backup, deployment, package retrieval, synchronization, CI/CD, monitoring and administrative transfer tools routinely create substantial TLS traffic." },
            MinimumConfidence = 81,
            WindowThreshold = 4,
            Window = TimeSpan.FromSeconds(120),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+linux_transfer_process+public_tls_peer+payload_burst",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive shaped observation and independent benign near miss",
                "missing and contradictory telemetry",
                "duplicate IDs, reverse time and window expiry where stateful",
                "cooldown suppression and recovery",
                "fixed evidence privacy, non-convergence, Candidate Shadow and registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research666TimedWindow _timed = new();

        public R736_LinuxNonBrowserTlsPayloadBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research736Evidence.Tls443(r)
                || !Research736Evidence.LinuxTransferProcess(r)
                || r.L4Len is null or < 900 or > 8192
                || !_timed.Observe(r.Source + "|" + r.Destination + "|" + r.ProcessId,
                    r.Id, r.L4Len.Value, context.TimestampUtc, 4, false, 5000))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1510", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "linux_nonbrowser_external_tls_payload_burst", "rule"),
                new DetectionEvidenceItem("outcome", "tls_payload_burst_only_file_source_and_exfiltration_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Linux transfer-tool external TLS payload burst observed; file source, unique bytes, upload semantics and exfiltration are unknown.",
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
