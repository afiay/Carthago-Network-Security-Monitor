// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 tests executed; workbook.R2634.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R796_FrpcInternalThenExternalSynRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R796",
            Name: "frpc-attributed internal proxy-leg then public TLS-port SYN",
            Category: "EvasionTunnel",
            Description: "frpc-attributed internal proxy-leg then public TLS-port SYN. Packet/process shape only; no authorization, exploitation, transfer completion, command execution or compromise inferred.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R796.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R796",
            Name = "frpc-attributed internal proxy-leg then public TLS-port SYN",
            Category = "EvasionTunnel",
            Description = "workbook.R2634: admitted only an independent bounded packet/process evidence shape; the source analytic requires endpoint, audit, allowlist or outcome telemetry not presently established.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id", "destination.port", "tcp.flags" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Coherent typed fields, strict directionality, unique packet IDs and this rule's own network predicate.", "Instance-owned bounded monotonic UTC correlation state; source-only, no live reachability claimed." },
            NegativeConditions = new[] { "Missing or contradictory transport/process, duplicate IDs, reversed/expired time and cooldown repeats fail closed.", "No free-form Info assertions, credentials, raw payload, endpoint event, authorization, C2 or impact claims." },
            FalsePositives = new[] { "Authorized maintenance, software deployment, operations, inventory, troubleshooting, and field engineering may generate these shapes." },
            MinimumConfidence = 80,
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "R796_seq_distinct_provenance",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive/benign", "contradictory/missing telemetry", "duplicate/reverse-time/expiry", "cooldown recovery", "privacy", "Candidate Shadow", "independence/registry uniqueness" }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _sequence = new();

        public R796_FrpcInternalThenExternalSynRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            if (Research786NetworkEvidence.Internal(r) && Research676Evidence.Syn(r)
                && Research676Evidence.Process(r, "frpc", "frpc.exe")
                && r.DestinationPort == 1080)
            {
                _sequence.Observe(r.Source! + "|" + r.ProcessId, r.Id, context.TimestampUtc, true, 60);
                return NoMatch();
            }
            if (!Research786NetworkEvidence.PrivatePublic(r) || !Research676Evidence.Syn(r)
                || !Research676Evidence.Process(r, "frpc", "frpc.exe")
                || r.DestinationPort != 443
                || !_sequence.Observe(r.Source! + "|" + r.ProcessId, r.Id, context.TimestampUtc, false, 60))
                return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2634", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "r796_seq_typed_network_observation", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_authorization_causality_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "frpc-attributed internal proxy-leg then public TLS-port SYN observed; asset role, causal context and outcome unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "typed-packet-or-local-process-evidence");
                    confidence.AddEvidence(0.33, "independent-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-monotonic-correlation");
                },
                count: 2, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
