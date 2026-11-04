// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R1647.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R743_EsxiManagementProcessFixedSizeEgressCadenceRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R743",
            Name: "ESXi management-process fixed-size uncommon-port egress cadence",
            Category: "EvasionInfra",
            Description: "hostd, vpxa, or vmx is associated with three similarly sized raw TCP payload observations to one public uncommon port at regular 9–31 second intervals. Encoded data, lookup tables, file contents, tunnel establishment and command-and-control are not observed.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R743.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R743",
            Name = "ESXi management-process fixed-size uncommon-port egress cadence",
            Category = "EvasionInfra",
            Description = "workbook.R1647: the source analytic correlates ESXi encoding activity with asymmetric/fixed outbound traffic. Carthago lacks shell encoding evidence, so this rule retains exact hypervisor process attribution plus fixed-size uncommon-port cadence only.",
            Severity = SeverityLevel.Low,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "destination.port", "process.name", "process.id", "l4.length" },
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
            FalsePositives = new[] { "Vendor telemetry, health polling, custom management agents and support tooling can use regular fixed-size messages on non-standard ports." },
            MinimumConfidence = 78,
            WindowThreshold = 3,
            Window = TimeSpan.FromSeconds(120),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+esxi_process+public_uncommon_port+fixed_size_cadence",
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
        private readonly Research676CadenceWindow _cadence = new();

        public R743_EsxiManagementProcessFixedSizeEgressCadenceRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research736Evidence.RawTcpPayload(r)
                || !Research736Evidence.HypervisorProcess(r)
                || !Research736Evidence.UncommonTcpPort(r.DestinationPort)
                || r.L4Len is null or < 100 or > 1000
                || !_cadence.Observe(r.Source + "|" + r.Destination + "|" + r.DestinationPort + "|" + r.ProcessId,
                    r.Id, r.L4Len.Value, context.TimestampUtc, 3, true))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1647", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "esxi_management_process_fixed_size_uncommon_port_cadence", "rule"),
                new DetectionEvidenceItem("outcome", "packet_cadence_only_encoding_and_c2_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Low,
                "ESXi management-process fixed-size uncommon-port egress cadence observed; encoding, file contents, tunnel and C2 semantics are unknown.",
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
