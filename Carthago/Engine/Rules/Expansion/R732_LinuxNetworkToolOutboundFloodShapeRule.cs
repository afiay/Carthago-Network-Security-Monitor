// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook workbook.R1501.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R732_LinuxNetworkToolOutboundFloodShapeRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R732",
            Name: "Linux network-tool outbound SYN/UDP flood shape",
            Category: "Network",
            Description: "bash, sh, python, curl, or wget is associated with twelve outbound SYN or small UDP observations to one public peer/port within ten seconds. Kernel throughput, resource exhaustion, spoofing, victim impact and denial of service are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R732.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R732",
            Name = "Linux network-tool outbound SYN/UDP flood shape",
            Category = "Network",
            Description = "workbook.R1501: the source analytic detects Linux userland/kernel processes generating high-rate ICMP/UDP/TCP traffic. Carthago narrows it to attributed TCP SYN or bounded UDP bursts because ICMP/process provenance is unavailable.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "protocol", "destination.port", "process.name", "process.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed packet fields plus the exact process/network predicate defined by this independent candidate.",
                "Correlated rules accept only unique packet IDs in monotonic UTC order inside a bounded rule-owned window.",
                "Only the observed process association, network shape, request classification or packet burst is asserted."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, invalid endpoints and free-form Info-only assertions.",
                "Reject duplicate packet IDs, reverse time, expired windows and cooldown repeats.",
                "Do not infer command-line arguments, asset role, file access, successful transfer, authenticated endpoint state, C2, DoS impact, exploit success or compromise."
            },
            FalsePositives = new[] { "Load generators, diagnostics, package automation, scanners, monitoring probes and administrator scripts can legitimately create brief high-rate network bursts." },
            MinimumConfidence = 80,
            WindowThreshold = 12,
            Window = TimeSpan.FromSeconds(10),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+linux_network_tool_pid+peer+port+burst",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive real-life-shaped sample and benign near miss",
                "missing and contradictory telemetry",
                "duplicate ID, reverse time and window expiry for correlated candidates",
                "cooldown suppression and recovery",
                "fixed evidence privacy, Candidate Shadow and unique registry"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research726BurstWindow _burst = new();

        public R732_LinuxNetworkToolOutboundFloodShapeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research726Evidence.FloodShape(r)
                || !Research726Evidence.Process(r, "bash", "sh", "zsh", "python", "python3", "curl", "wget")
                || !_burst.Observe(r.Source + "|" + r.Destination + "|" + r.DestinationPort + "|" + r.Protocol + "|" + r.ProcessId,
                    r.Id, context.TimestampUtc, 12, 10))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1501", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "linux_network_tool_outbound_syn_or_udp_burst", "rule"),
                new DetectionEvidenceItem("outcome", "packet_burst_only_dos_impact_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Linux network-tool outbound packet burst observed; throughput, spoofing, victim impact and denial-of-service outcome are unknown.",
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
