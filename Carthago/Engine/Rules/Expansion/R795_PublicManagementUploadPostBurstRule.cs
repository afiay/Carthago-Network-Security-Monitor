// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; source-only xUnit, 0 tests executed. workbook.R1847.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R795_PublicManagementUploadPostBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R795",
            Name: "Large public HTTP POST burst to firmware upload endpoint",
            Category: "WebAttack",
            Description: "Large public HTTP POST burst to firmware upload endpoint. A bounded observation only; no config change, successful authentication, transfer, exploitation or compromise established.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R795.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R795",
            Name = "Large public HTTP POST burst to firmware upload endpoint",
            Category = "WebAttack",
            Description = "workbook.R1847: narrowed to actually modeled packet, DNS, HTTP, TLS, and optional local-process telemetry; original audit/outcome evidence is unavailable.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http },
            RequiredFields = new[] { "source", "destination", "packet.id", "http.method", "http.uri", "destination.port", "l4.length" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Only coherent typed fields and this rule's distinct temporal/network predicate qualify.", "Each instance has independent, bounded, monotonic UTC packet-ID correlation state." },
            NegativeConditions = new[] { "Reject duplicate packet ID, reversed time, wrong direction, expired observations, missing or contradictory telemetry.", "Never infer authenticated user, endpoint configuration change, successful file transfer, C2, causal compromise or impact." },
            FalsePositives = new[] { "Authorized administration, failover, service deployment and maintenance may produce matching network sequences." },
            MinimumConfidence = 80,
            WindowThreshold = 4,
            Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "R795_independent_count_network_predicate",
            TuningKnobs = new[] { "Mode", "ApprovedAssets", "ApprovedProcesses", "ApprovedPeers", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive and benign near miss", "missing/contradictory fields", "replay/reverse-time/expiry", "cooldown recovery", "privacy", "Candidate/Shadow", "non-convergence and unique registry" }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research736CountWindow _count = new();

        public R795_PublicManagementUploadPostBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            if (!Research786NetworkEvidence.PublicPrivate(r) || !Research786NetworkEvidence.TcpData(r)
                || r.DestinationPort != 8080 || r.L4Len is < 1200 or > 8192
                || !WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                || method != "POST"
                || !uri.StartsWith("/system/firmware/upload", StringComparison.OrdinalIgnoreCase))
                return NoMatch();
            var key = r.Source + "|" + r.Destination + "|firmware-post";
            if (!_count.Observe(key, r.Id, r.L4Len!.Value, context.TimestampUtc,
                4, 45, 9000)) return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1847", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "r795_count_typed_network_observation", "rule"),
                new DetectionEvidenceItem("outcome", "packet_sequence_only_endpoint_intent_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Large public HTTP POST burst to firmware upload endpoint observed; causal context, endpoint state and outcomes unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "typed-observable-network-fields");
                    confidence.AddEvidence(0.33, "workbook-derived-independent-predicate");
                    confidence.AddCorrelation(0.12, "bounded-ordered-evidence");
                },
                count: 4, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
