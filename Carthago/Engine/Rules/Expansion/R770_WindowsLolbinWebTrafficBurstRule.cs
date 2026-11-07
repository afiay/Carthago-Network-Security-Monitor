// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R2817.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R770_WindowsLolbinWebTrafficBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R770",
            Name: "Windows LOLBIN outbound web-traffic burst",
            Category: "EvasionTunnel",
            Description: "regsvr32, mshta, wscript, or cscript is associated with eight HTTP request or TLS/443 payload observations to one public peer within twenty seconds. Process novelty, response volume, script content and command-and-control are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R770.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R770",
            Name = "Windows LOLBIN outbound web-traffic burst",
            Category = "EvasionTunnel",
            Description = "workbook.R2817: the Windows obfuscated-C2 analytic targets uncommon processes with excessive HTTP(S). Carthago replaces unavailable novelty/baseline evidence with a narrow LOLBIN process family and bounded web-traffic burst.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "process.name", "process.id", "http_or_tls", "l4.length" },
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
            FalsePositives = new[] { "Enterprise scripting, software deployment, legacy applications and administrative automation can generate repeated web traffic from these utilities." },
            MinimumConfidence = 82,
            WindowThreshold = 8,
            Window = TimeSpan.FromSeconds(20),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+windows_lolbin_pid+public_web_peer+burst",
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

        public R770_WindowsLolbinWebTrafficBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research766Evidence.WindowsLolbinWebPacket(r, out var size)
                || !_window.Observe(r.Source + "|" + r.Destination + "|" + r.DestinationPort + "|" + r.ProcessId,
                    r.Id, size, context.TimestampUtc, 8, 20))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2817", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "windows_lolbin_http_or_tls_burst", "rule"),
                new DetectionEvidenceItem("outcome", "web_traffic_burst_only_process_novelty_and_c2_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Windows LOLBIN outbound web-traffic burst observed; process novelty, response asymmetry, script content and command-and-control are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 8,
                windowSeconds: 20);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
