// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R1335.
using System;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R758_PublicUncommonTriggerThenReverseSynRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R758",
            Name: "Public uncommon-port trigger followed by reverse SYN to origin",
            Category: "EvasionTunnel",
            Description: "A low-volume public-to-private TCP SYN to an uncommon high port is followed within 90 seconds by a TCP SYN from that private host back to the same public source. Packet-filter installation, raw-socket activity, accepted sessions, reverse-shell semantics and compromise are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R758.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R758",
            Name = "Public uncommon-port trigger followed by reverse SYN to origin",
            Category = "EvasionTunnel",
            Description = "workbook.R1335: the source analytic includes packet-capture/raw-socket telemetry. Carthago narrows it to the observable two-stage network trigger and reverse-connection shape.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "public_source", "private_destination", "tcp.flags", "destination.port", "reverse_source", "reverse_destination" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed producer fields and this independent rule-specific predicate.",
                "Process identity, where used, is best-effort local tuple enrichment rather than authenticated endpoint identity.",
                "Stateful rules accept unique packet IDs in monotonic UTC order inside bounded rule-owned windows."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, malformed endpoints and Info-only assertions.",
                "Reject duplicate packet IDs, reverse time, expired sequences and cooldown repeats.",
                "Do not infer file access, credentials, command-line arguments, successful authentication, exploit success, C2 control, transfer completion or compromise."
            },
            FalsePositives = new[] { "NAT traversal, diagnostics, peer-to-peer applications, security testing and administrator workflows can generate trigger/reverse-connection sequences." },
            MinimumConfidence = 80,
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(90),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "private_host+public_trigger_peer+reverse_syn_sequence",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive shaped sample and rule-specific benign near miss",
                "missing and contradictory telemetry",
                "duplicate ID, reverse-time and expiry where stateful",
                "cooldown suppression and recovery",
                "privacy, non-convergence, Candidate Shadow and registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research756PeerSequenceWindow _sequence = new();

        public R758_PublicUncommonTriggerThenReverseSynRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (Research756Evidence.PublicUncommonTrigger(r))
                {
                    _sequence.Observe(r.Destination!, r.Source!, r.Id, context.TimestampUtc, true, 90);
                    return NoMatch();
                }
            
                if (!Research756Evidence.ReversePublicSyn(r)
                    || !_sequence.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc, false, 90))
                    return NoMatch();

            var cool = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (cool == WebSignatureObservation.None) return NoMatch();
            if (cool == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1335", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "public_uncommon_syn_then_reverse_syn_same_peer", "rule"),
                new DetectionEvidenceItem("outcome", "trigger_reverse_network_sequence_only_raw_socket_and_shell_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Public uncommon-port trigger followed by reverse SYN to the same origin observed; raw-socket setup, accepted connection, reverse shell and compromise are unknown.",
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
