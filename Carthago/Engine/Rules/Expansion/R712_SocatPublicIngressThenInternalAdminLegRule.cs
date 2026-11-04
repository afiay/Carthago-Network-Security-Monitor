// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R2049.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R712_SocatPublicIngressThenInternalAdminLegRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R712",
            Name: "Socat process receives public SYN then contacts internal admin service",
            Category: "EvasionTunnel",
            Description: "The same best-effort local Socat PID receives a public high-port SYN and then initiates a SYN from that local host to a different private admin-service peer within 30 seconds. Two SYNs do not prove port forwarding, encapsulation, payload relay, or a successful connection.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R712.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R712",
            Name = "Socat process receives public SYN then contacts internal admin service",
            Category = "EvasionTunnel",
            Description = "Workbook R2049: the Linux source analytic also expects connect/bind or forwarding parameters. Carthago narrows it to a process-attributed public-ingress to private-admin two-leg sequence, separate from R674's different process set and public egress.",
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
            FalsePositives = new[] { "Approved reverse proxies, bastions, troubleshooting relays, and lab tunneling with Socat can produce this shape." },
            MinimumConfidence = 84,
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(30),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "local_host+socat_pid+public_ingress_peer+private_admin_peer",
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

        public R712_SocatPublicIngressThenInternalAdminLegRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research706Evidence.TcpSyn(r) || !Research706Evidence.Socat(r))
                return NoMatch();
            var first = Research706Evidence.PublicToPrivate(r) && r.DestinationPort is > 1024 and <= 65535;
            var second = Research706Evidence.PrivatePair(r) && Research706Evidence.AdminPort(r.DestinationPort);
            if (!first && !second) return NoMatch();
            var local = first ? r.Destination! : r.Source!;
            var peer = first ? r.Source! : r.Destination!;
            var process = NetworkBatch266270Evidence.Process(r);
            if (!_legs.Observe(local + "|" + r.ProcessId + "|" + process, peer, r.Id, context.TimestampUtc, first))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2049", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "socat_public_ingress_then_private_admin_leg", "rule"),
                new DetectionEvidenceItem("outcome", "socat_relay_shaped_syn_pair_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Socat public-ingress then internal-admin SYN pair observed; forwarding, payload relay, and connection success are unknown.",
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
