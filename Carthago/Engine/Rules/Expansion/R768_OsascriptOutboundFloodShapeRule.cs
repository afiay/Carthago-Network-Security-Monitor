// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R1968.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R768_OsascriptOutboundFloodShapeRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R768",
            Name: "osascript outbound SYN/UDP flood shape",
            Category: "Network",
            Description: "osascript is associated with twelve outbound TCP SYN or small UDP observations to one public peer and port within ten seconds. UI context, packet-generator command line, throughput, spoofing, victim impact and denial-of-service outcome are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R768.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R768",
            Name = "osascript outbound SYN/UDP flood shape",
            Category = "Network",
            Description = "workbook.R1968: the macOS flood analytic includes ping/curl/custom-script activity. Carthago uses the macOS-specific osascript process signal and a bounded SYN/UDP packet-rate shape to avoid duplicating Linux/Windows network-tool rules.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "protocol", "destination.port", "process.name", "process.id" },
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
            FalsePositives = new[] { "Synthetic monitoring, load generation, security testing and administrator automation can intentionally generate brief packet bursts." },
            MinimumConfidence = 80,
            WindowThreshold = 12,
            Window = TimeSpan.FromSeconds(10),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+osascript_pid+public_peer+port+packet_burst",
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
        private readonly Research726BurstWindow _burst = new();

        public R768_OsascriptOutboundFloodShapeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research726Evidence.FloodShape(r)
                || !Research766Evidence.MacFloodProcess(r)
                || !_burst.Observe(r.Source + "|" + r.Destination + "|" + r.DestinationPort + "|" + r.Protocol + "|" + r.ProcessId,
                    r.Id, context.TimestampUtc, 12, 10))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1968", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "osascript_outbound_syn_or_udp_burst", "rule"),
                new DetectionEvidenceItem("outcome", "packet_burst_only_dos_impact_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "osascript outbound packet burst observed; UI context, throughput, spoofing, victim impact and denial-of-service outcome are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 12,
                windowSeconds: 10);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
