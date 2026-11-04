// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R1982.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R753_OsascriptExternalTlsRecurrentCadenceRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R753",
            Name: "osascript recurrent external TLS cadence",
            Category: "ExfiltrationAdvanced",
            Description: "osascript is associated with three similarly sized TLS/443 payload observations to one public peer at 30–90 second intervals. LaunchAgent scheduling, user identity, local file access, request content and exfiltration are not observed.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R753.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R753",
            Name = "osascript recurrent external TLS cadence",
            Category = "ExfiltrationAdvanced",
            Description = "workbook.R1982: the source analytic targets recurring launchd/LaunchAgent transfers. Carthago lacks scheduler audit, so this rule keeps exact osascript attribution plus a regular low-volume TLS cadence that does not overlap the large-payload burst rule.",
            Severity = SeverityLevel.Low,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Tls, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "tls.sni", "tls.version", "process.name", "process.id", "l4.length" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent TLS/process fields and three unique monotonic observations inside the bounded cadence window.",
                "Require osascript attribution and low-volume payload sizes to remain distinct from large TLS burst rules.",
                "Only the network cadence is asserted."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, malformed endpoints and free-form Info-only assertions.",
                "Reject duplicate packet IDs, reverse time, irregular cadence, expired windows and cooldown repeats.",
                "Do not infer LaunchAgent scheduling, file reads, request contents or exfiltration."
            },
            FalsePositives = new[] { "Automation, AppleScript integrations, monitoring, enterprise management and periodic application polling can produce regular osascript-associated TLS traffic." },
            MinimumConfidence = 78,
            WindowThreshold = 3,
            Window = TimeSpan.FromSeconds(240),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+osascript+public_tls_peer+regular_small_payload_cadence",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive regular cadence and irregular-size/timing near miss",
                "missing and contradictory producer fields",
                "duplicate IDs, reverse time and expiry",
                "cooldown suppression and recovery",
                "evidence privacy, non-convergence, Candidate Shadow and registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research736CadenceWindow _cadence = new();

        public R753_OsascriptExternalTlsRecurrentCadenceRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research746Evidence.Tls443(r)
                || !Research746Evidence.MacCadenceProcess(r)
                || r.L4Len is null or < 100 or > 800
                || !_cadence.Observe(r.Source + "|" + r.Destination + "|" + r.ProcessId,
                    r.Id, r.L4Len.Value, context.TimestampUtc, 3, 30, 90, 80, 240))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1982", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "osascript_regular_external_tls_cadence", "rule"),
                new DetectionEvidenceItem("outcome", "network_cadence_only_scheduler_and_exfiltration_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Low,
                "osascript recurrent external TLS cadence observed; scheduler, local file source, request content and exfiltration are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 3,
                windowSeconds: 240);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
