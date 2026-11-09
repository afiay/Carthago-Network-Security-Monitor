// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 tests executed; workbook.R2690.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R801_CipIdentityThenModbusSynRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R801",
            Name: "EtherNet/IP ListIdentity probe then Modbus SYN to same private device",
            Category: "IotOt",
            Description: "EtherNet/IP ListIdentity probe then Modbus SYN to same private device. Packet/process shape only; no authorization, exploitation, transfer completion, command execution or compromise inferred.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R801.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R801",
            Name = "EtherNet/IP ListIdentity probe then Modbus SYN to same private device",
            Category = "IotOt",
            Description = "workbook.R2690: admitted only an independent bounded packet/process evidence shape; the source analytic requires endpoint, audit, allowlist or outcome telemetry not presently established.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.OtIcsProtocol },
            RequiredFields = new[] { "source", "destination", "packet.id", "application.protocol", "process.id", "destination.port" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Coherent typed fields, strict directionality, unique packet IDs and this rule's own network predicate.", "Instance-owned bounded monotonic UTC correlation state; source-only, no live reachability claimed." },
            NegativeConditions = new[] { "Missing or contradictory transport/process, duplicate IDs, reversed/expired time and cooldown repeats fail closed.", "No free-form Info assertions, credentials, raw payload, endpoint event, authorization, C2 or impact claims." },
            FalsePositives = new[] { "Authorized maintenance, software deployment, operations, inventory, troubleshooting, and field engineering may generate these shapes." },
            MinimumConfidence = 80,
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(50),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "R801_seq_distinct_provenance",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive/benign", "contradictory/missing telemetry", "duplicate/reverse-time/expiry", "cooldown recovery", "privacy", "Candidate Shadow", "independence/registry uniqueness" }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _sequence = new();

        public R801_CipIdentityThenModbusSynRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            if (!Research786NetworkEvidence.Internal(r) || !Research676Evidence.Process(r, "python", "python.exe"))
                return NoMatch();
            var key = r.Source + "|" + r.Destination + "|" + r.ProcessId;
            if (Research786NetworkEvidence.UdpData(r) && r.DestinationPort == 44818
                && r.L4Len == 24
                && string.Equals(r.ApplicationProtocol, "ethernetip.listidentity", StringComparison.Ordinal))
            {
                _sequence.Observe(key, r.Id, context.TimestampUtc, true, 50);
                return NoMatch();
            }
            if (!Research676Evidence.Syn(r) || r.DestinationPort != 502
                || !_sequence.Observe(key, r.Id, context.TimestampUtc, false, 50)) return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2690", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "r801_seq_typed_network_observation", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_authorization_causality_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "EtherNet/IP ListIdentity probe then Modbus SYN to same private device observed; asset role, causal context and outcome unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "typed-packet-or-local-process-evidence");
                    confidence.AddEvidence(0.33, "independent-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-monotonic-correlation");
                },
                count: 2, windowSeconds: 50);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
