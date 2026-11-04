// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R1727.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R714_NetcatInternalMultiPortProbeRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R714",
            Name: "Netcat process probes four ports on one private peer",
            Category: "NetworkDiscovery",
            Description: "One best-effort Netcat/Ncat PID sends SYNs to four distinct ports on the same private peer within 30 seconds. This is a service-discovery-shaped probe only; container context, vulnerability state, connect success, and lateral movement are not observed.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R714.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R714",
            Name = "Netcat process probes four ports on one private peer",
            Category = "NetworkDiscovery",
            Description = "Workbook R1727: the workbook spans container socket/exec telemetry that Carthago does not expose. This candidate uses only process-attributed same-peer multi-port SYN behavior, distinct from R680's different-process multi-host fanout.",
            Severity = SeverityLevel.Low,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "tcp.flags", "process.name", "process.id", "destination.port" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed producer fields and this rule's independent exact predicate.",
                "Bounded correlation uses unique packet IDs and UTC ordering where multiple observations are required.",
                "Only the observable packet, flow, parser, or best-effort process association is claimed."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory protocol fields, wrong network direction, and Info-only indicators.",
                "Reject packet-ID replay, out-of-order state, stale windows, and cooldown repeats.",
                "Do not infer authentication, exploit success, file writes, command lines, transfer completion, or compromise."
            },
            FalsePositives = new[] { "Network troubleshooting, service checks, development, inventory, and authorized security scanning with Netcat/Ncat can trigger this candidate." },
            MinimumConfidence = 80,
            WindowThreshold = 4,
            Window = TimeSpan.FromSeconds(30),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "local_host+netcat_pid+private_peer+four_distinct_ports",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive real-life-shaped case and benign near miss",
                "wrong or missing telemetry and contradictory protocol fields",
                "duplicate packet ID and out-of-order timestamp where relevant",
                "window expiry and cooldown behavior",
                "privacy/redaction, registry uniqueness, Candidate Shadow, and non-convergence"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research706DistinctWindow _ports = new();

        public R714_NetcatInternalMultiPortProbeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research706Evidence.TcpSyn(r)
                || !Research706Evidence.Netcat(r)
                || !Research706Evidence.PrivatePair(r))
                return NoMatch();
            var process = NetworkBatch266270Evidence.Process(r);
            if (!_ports.Observe(r.Source + "|" + r.Destination + "|" + r.ProcessId + "|" + process,
                    r.DestinationPort!.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    r.Id, context.TimestampUtc, 4, 30))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1727", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "netcat_same_private_peer_four_port_syn_probe", "rule"),
                new DetectionEvidenceItem("outcome", "netcat_service_discovery_shape_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Low,
                "Netcat/Ncat sent SYNs to four distinct ports on one private peer; service discovery intent and connect outcomes are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 4,
                windowSeconds: 30);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
