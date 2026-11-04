// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R1811.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R711_PlinkSshThenInternalAdminLegRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R711",
            Name: "Plink or PuTTY process contacts public SSH then internal admin service",
            Category: "EvasionTunnel",
            Description: "The same best-effort local Plink/PuTTY PID first sends an outbound SSH SYN to a public peer and then an outbound SYN to a different private admin-service peer within 30 seconds. This does not prove SSH port forwarding, encapsulated RDP/SMB, authentication, or an established tunnel.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R711.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R711",
            Name = "Plink or PuTTY process contacts public SSH then internal admin service",
            Category = "EvasionTunnel",
            Description = "Workbook R1811: the workbook includes command/process and encapsulation evidence unavailable to Carthago. The implementation retains the exact Plink/PuTTY process identity and a two-leg network shape rather than inferring command-line forwarding flags.",
            Severity = SeverityLevel.Medium,
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
            FalsePositives = new[] { "Approved administrators can use Plink/PuTTY for jump-host workflows, port forwarding, and maintenance." },
            MinimumConfidence = 83,
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(30),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "local_host+plink_pid+public_ssh_peer+private_admin_peer",
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
        private readonly Research696RelayWindow _legs = new();

        public R711_PlinkSshThenInternalAdminLegRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research706Evidence.TcpSyn(r) || !Research706Evidence.Plink(r))
                return NoMatch();
            var first = Research706Evidence.PrivateToPublic(r) && r.DestinationPort == 22;
            var second = Research706Evidence.PrivatePair(r) && Research706Evidence.AdminPort(r.DestinationPort);
            if (!first && !second) return NoMatch();
            var local = r.Source!;
            var peer = r.Destination!;
            var process = NetworkBatch266270Evidence.Process(r);
            if (!_legs.Observe(local + "|" + r.ProcessId + "|" + process, peer, r.Id, context.TimestampUtc, first))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1811", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "plink_public_ssh_then_private_admin_leg", "rule"),
                new DetectionEvidenceItem("outcome", "plink_dual_leg_tunnel_shape_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Plink/PuTTY public-SSH then internal-admin two-leg SYN sequence observed; forwarding and tunnel establishment are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 2,
                windowSeconds: 30);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
