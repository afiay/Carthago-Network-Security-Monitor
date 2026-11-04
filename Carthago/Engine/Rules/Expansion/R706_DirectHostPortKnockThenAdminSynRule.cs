// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R1445.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R706_DirectHostPortKnockThenAdminSynRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R706",
            Name: "Public source three-port knock followed by private-host admin SYN",
            Category: "EvasionTunnel",
            Description: "A public source sends SYNs to exactly three distinct high ports on one private host, then an admin-service SYN within 60 seconds. This does not prove closed-port responses, firewall changes, listener activation, magic-packet handling, or a successful session.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R706.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R706",
            Name = "Public source three-port knock followed by private-host admin SYN",
            Category = "EvasionTunnel",
            Description = "Workbook R1445: the source analytic also requires host firewall/listener change and successful connection evidence that Carthago does not possess. This candidate is limited to an ordered direct-host SYN sequence and is distinct from R676's unicast/broadcast/network-address pattern.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "tcp.flags", "source.port", "destination.port" },
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
            FalsePositives = new[] { "Authorized port-knock gateways, scanners, diagnostics, and security testing can generate the same ordered SYN shape." },
            MinimumConfidence = 82,
            WindowThreshold = 4,
            Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+private_host+three_distinct_knock_ports+admin_final",
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
        private readonly Research706KnockWindow _knock = new();

        public R706_DirectHostPortKnockThenAdminSynRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research706Evidence.TcpSyn(r) || !Research706Evidence.PublicToPrivate(r))
                return NoMatch();
            var final = Research706Evidence.AdminPort(r.DestinationPort);
            var knock = r.DestinationPort is > 1024 and <= 65535 && !final;
            if (!knock && !final) return NoMatch();
            if (!_knock.Observe(r.Source + "|" + r.Destination, r.DestinationPort!.Value, r.Id, context.TimestampUtc, final))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1445", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "direct_host_three_port_knock_then_admin_syn", "rule"),
                new DetectionEvidenceItem("outcome", "ordered_syn_signaling_shape_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Public-to-private three-port knock followed by admin-service SYN observed; host-side activation and connection success are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 4,
                windowSeconds: 60);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
