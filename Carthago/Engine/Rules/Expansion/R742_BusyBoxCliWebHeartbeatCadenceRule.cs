// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R1750.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R742_BusyBoxCliWebHeartbeatCadenceRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R742",
            Name: "BusyBox/curl/wget external TLS heartbeat-shaped cadence",
            Category: "EvasionTunnel",
            Description: "busybox, curl, or wget is associated with three similarly sized TLS/443 payload observations to one public peer at regular 9–31 second intervals. Common dead-drop, cloud-storage, code-repository and public-IP discovery hosts are excluded. Shell origin, HTTP content, command-and-control and server responses are not observed.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R742.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R742",
            Name = "BusyBox/curl/wget external TLS heartbeat-shaped cadence",
            Category = "EvasionTunnel",
            Description = "workbook.R1750: the source analytic describes ESXi shell/management-daemon web C2. Carthago cannot establish shell origin or C2 content, so this candidate keeps only a CLI-tool process plus a regular encrypted web cadence.",
            Severity = SeverityLevel.Low,
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
            FalsePositives = new[] { "Update agents, health checks, package retrieval, telemetry, monitoring and retry loops can produce regular TLS cadences from CLI tools." },
            MinimumConfidence = 78,
            WindowThreshold = 3,
            Window = TimeSpan.FromSeconds(120),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+busybox_web_process+public_tls_peer+regular_cadence",
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

        public R742_BusyBoxCliWebHeartbeatCadenceRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research736Evidence.Tls443(r)
                || !Research736Evidence.BusyBoxWebProcess(r)
                || Research736Evidence.CommonServiceHost(r.Sni)
                || r.L4Len is null or < 100 or > 1000
                || !_cadence.Observe(r.Source + "|" + r.Destination + "|" + r.ProcessId,
                    r.Id, r.L4Len.Value, context.TimestampUtc, 3, 9, 31, 100, 120))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1750", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "busybox_cli_external_tls_regular_cadence", "rule"),
                new DetectionEvidenceItem("outcome", "tls_cadence_only_c2_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Low,
                "BusyBox/curl/wget external TLS heartbeat-shaped cadence observed; shell origin, encrypted content and C2 control are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 3,
                windowSeconds: 120);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
