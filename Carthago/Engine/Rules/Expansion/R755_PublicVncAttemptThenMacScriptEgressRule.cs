// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R1775.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R755_PublicVncAttemptThenMacScriptEgressRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R755",
            Name: "Public VNC attempt followed by macOS-style script egress",
            Category: "LateralMovement",
            Description: "A public-to-private TCP SYN to VNC/5900 is followed within 90 seconds by outbound public traffic from the same private host attributed to osascript, zsh, curl, or python3. VNC authentication, exploit success, process parentage, service crash, causal linkage and compromise are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R755.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R755",
            Name = "Public VNC attempt followed by macOS-style script egress",
            Category = "LateralMovement",
            Description = "workbook.R1775: the source analytic ties exposed macOS remote services to post-exploit child processes and egress. Carthago cannot see crashes or process lineage, so this candidate requires only the bounded network sequence: VNC connection attempt then script/tool-attributed egress from the same host.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "public_source", "private_destination", "tcp.flags", "destination.port", "follow_on_source", "follow_on_process.name" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require a coherent public-to-private VNC SYN and a later public egress observation from the same private host.",
                "Require the follow-on observation to carry best-effort local attribution to osascript, zsh, curl or python3.",
                "Only the temporal network sequence is asserted."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport fields, non-VNC ingress, wrong host correlation and free-form Info-only assertions.",
                "Reject duplicate packet IDs, reverse time, sequences older than 90 seconds and cooldown repeats.",
                "Do not infer authentication, exploit success, service crash, process parentage, causality or compromise."
            },
            FalsePositives = new[] { "Remote support, vulnerability assessment, administrator activity and unrelated automation on the same host can occur near a VNC connection attempt and create coincidental correlation." },
            MinimumConfidence = 80,
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(90),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "private_host+vnc_ingress_attempt+script_egress_sequence",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive VNC-attempt then script-egress sequence and unrelated-host near miss",
                "missing and contradictory producer fields",
                "duplicate IDs, reverse time and expiry",
                "cooldown suppression and recovery",
                "evidence privacy, non-convergence, Candidate Shadow and registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research746VncBridgeWindow _bridge = new();

        public R755_PublicVncAttemptThenMacScriptEgressRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (Research746Evidence.VncIngressSyn(r))
            {
                _bridge.Observe(r.Destination!, r.Id, context.TimestampUtc, true);
                return NoMatch();
            }

            if (!Research746Evidence.MacScriptEgress(r)
                || !_bridge.Observe(r.Source!, r.Id, context.TimestampUtc, false))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1775", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "public_vnc_attempt_then_mac_script_egress", "rule"),
                new DetectionEvidenceItem("outcome", "temporal_network_sequence_only_exploit_and_causality_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Public VNC attempt followed by script/tool-attributed egress from the same private host observed; authentication, exploit success, causality and compromise are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 2,
                windowSeconds: 90);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
