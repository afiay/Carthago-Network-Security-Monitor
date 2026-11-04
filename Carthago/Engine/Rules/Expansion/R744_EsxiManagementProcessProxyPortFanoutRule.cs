// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R1632.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R744_EsxiManagementProcessProxyPortFanoutRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R744",
            Name: "ESXi management-process public proxy-port fanout",
            Category: "EvasionTunnel",
            Description: "hostd, vpxa, or vmx initiates TCP SYNs to three distinct public peers on proxy/tunnel-associated ports within one minute. Traffic forwarding, relay chaining, authenticated proxy use, multi-hop routing and malicious intent are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R744.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R744",
            Name = "ESXi management-process public proxy-port fanout",
            Category = "EvasionTunnel",
            Description = "workbook.R1632: the source analytic describes ESXi outbound relay/proxy behavior. Carthago cannot establish actual forwarding, so this candidate requires exact hypervisor-management process attribution plus distinct public proxy-port connection attempts.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "destination.port", "tcp.flags", "process.name", "process.id" },
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
            FalsePositives = new[] { "Vendor support, distributed management services, security tooling and unusual enterprise proxy designs can contact multiple public proxy-like endpoints." },
            MinimumConfidence = 80,
            WindowThreshold = 3,
            Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+esxi_process+three_public_proxy_port_peers",
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
        private readonly Research706DistinctWindow _peers = new();

        public R744_EsxiManagementProcessProxyPortFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research676Evidence.Syn(r)
                || !Research736Evidence.PrivateToPublic(r)
                || !Research736Evidence.HypervisorProcess(r)
                || !Research736Evidence.ProxyLikePort(r.DestinationPort)
                || !_peers.Observe(r.Source + "|" + r.ProcessId + "|" + r.DestinationPort,
                    r.Destination!, r.Id, context.TimestampUtc, 3, 60))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1632", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "esxi_management_process_three_public_proxy_port_peers", "rule"),
                new DetectionEvidenceItem("outcome", "proxy_port_fanout_only_forwarding_and_proxy_use_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "ESXi management-process public proxy-port fanout observed; traffic forwarding, relay chaining and authenticated proxy use are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 3,
                windowSeconds: 60);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
