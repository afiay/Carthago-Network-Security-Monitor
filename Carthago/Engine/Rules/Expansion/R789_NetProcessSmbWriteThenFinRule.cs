// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; source-only xUnit, 0 tests executed. workbook.R2063.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R789_NetProcessSmbWriteThenFinRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R789",
            Name: "Net-process SMB2 write request followed by TCP FIN",
            Category: "LateralMovement",
            Description: "Net-process SMB2 write request followed by TCP FIN. A bounded observation only; no config change, successful authentication, transfer, exploitation or compromise established.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R789.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R789",
            Name = "Net-process SMB2 write request followed by TCP FIN",
            Category = "LateralMovement",
            Description = "workbook.R2063: narrowed to actually modeled packet, DNS, HTTP, TLS, and optional local-process telemetry; original audit/outcome evidence is unavailable.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id", "application.protocol", "tcp.flags" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Only coherent typed fields and this rule's distinct temporal/network predicate qualify.", "Each instance has independent, bounded, monotonic UTC packet-ID correlation state." },
            NegativeConditions = new[] { "Reject duplicate packet ID, reversed time, wrong direction, expired observations, missing or contradictory telemetry.", "Never infer authenticated user, endpoint configuration change, successful file transfer, C2, causal compromise or impact." },
            FalsePositives = new[] { "Authorized administration, failover, service deployment and maintenance may produce matching network sequences." },
            MinimumConfidence = 80,
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "R789_independent_seq_network_predicate",
            TuningKnobs = new[] { "Mode", "ApprovedAssets", "ApprovedProcesses", "ApprovedPeers", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive and benign near miss", "missing/contradictory fields", "replay/reverse-time/expiry", "cooldown recovery", "privacy", "Candidate/Shadow", "non-convergence and unique registry" }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _sequence = new();

        public R789_NetProcessSmbWriteThenFinRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            if (!Research786NetworkEvidence.Coherent(r) || !r.IsTcp || !Research786NetworkEvidence.Internal(r)
                || !Research676Evidence.Process(r, "net", "net.exe")
                || r.DestinationPort != 445) return NoMatch();
            var key = r.Source + "|" + r.Destination + "|" + r.ProcessId;
            if (Research786NetworkEvidence.TcpData(r)
                && string.Equals(r.ApplicationProtocol, "smb2.write.request", StringComparison.Ordinal))
            {
                _sequence.Observe(key, r.Id, context.TimestampUtc, true, 45);
                return NoMatch();
            }
            if (r.TcpFlags is not (0x11 or 0x01) || r.L4Len is not (null or 0)
                || r.ApplicationProtocol != null || r.DnsQname != null
                || !_sequence.Observe(key, r.Id, context.TimestampUtc, false, 45)) return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2063", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "r789_seq_typed_network_observation", "rule"),
                new DetectionEvidenceItem("outcome", "packet_sequence_only_endpoint_intent_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Net-process SMB2 write request followed by TCP FIN observed; causal context, endpoint state and outcomes unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "typed-observable-network-fields");
                    confidence.AddEvidence(0.33, "workbook-derived-independent-predicate");
                    confidence.AddCorrelation(0.12, "bounded-ordered-evidence");
                },
                count: 2, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
