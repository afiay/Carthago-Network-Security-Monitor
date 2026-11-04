// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R1548.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R738_LinuxRecurrentTransferCadenceRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R738",
            Name: "Linux transfer-tool recurrent outbound payload cadence",
            Category: "ExfiltrationAdvanced",
            Description: "rsync, scp, sftp, rclone, curl, wget, or Python is associated with three similarly sized outbound TCP payload observations to the same public peer at regular 20–70 second intervals. Cron scheduling, user identity, file contents, transfer completion and exfiltration are not observed.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R738.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R738",
            Name = "Linux transfer-tool recurrent outbound payload cadence",
            Category = "ExfiltrationAdvanced",
            Description = "workbook.R1548: the workbook analytic targets cron/script-based recurring transfers. Carthago lacks cron and shell audit, so this rule is deliberately limited to a transfer-tool process plus a bounded regular network cadence.",
            Severity = SeverityLevel.Low,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "process.name", "process.id", "l4.length" },
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
            FalsePositives = new[] { "Health checks, synchronization, backups, deployment agents, telemetry and retry loops can produce regular transfer cadences." },
            MinimumConfidence = 78,
            WindowThreshold = 3,
            Window = TimeSpan.FromSeconds(180),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+transfer_process+public_peer+regular_payload_cadence",
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
        private readonly Research736CadenceWindow _cadence = new();

        public R738_LinuxRecurrentTransferCadenceRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research736Evidence.RawTcpPayload(r)
                || !Research736Evidence.LinuxTransferProcess(r)
                || r.L4Len is null or < 256 or > 4096
                || !_cadence.Observe(r.Source + "|" + r.Destination + "|" + r.DestinationPort + "|" + r.ProcessId,
                    r.Id, r.L4Len.Value, context.TimestampUtc, 3, 20, 70, 192, 180))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1548", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "linux_transfer_tool_regular_payload_cadence", "rule"),
                new DetectionEvidenceItem("outcome", "network_cadence_only_cron_and_exfiltration_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Low,
                "Linux transfer-tool recurrent outbound payload cadence observed; scheduler, file contents, transfer completion and exfiltration are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 3,
                windowSeconds: 180);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
