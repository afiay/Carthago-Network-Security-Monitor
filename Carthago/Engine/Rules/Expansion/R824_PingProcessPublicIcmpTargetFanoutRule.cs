// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit source authored first, 0 tests executed; workbook.R2857.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R824_PingProcessPublicIcmpTargetFanoutRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R824",
            Name: "ping-attributed ICMP echo to three distinct public hosts",
            Category: "NetworkDiscovery",
            Description: "ping-attributed ICMP echo to three distinct public hosts. Source-only network/process evidence; no authorization, compromise or successful outcome inferred.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R824.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R824",
            Name = "ping-attributed ICMP echo to three distinct public hosts",
            Category = "NetworkDiscovery",
            Description = "workbook.R2857: No macOS provenance, successful responses or internet discovery intent is known; only process-attributed ICMP echo packets.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id", "icmp.type_code", "destination" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Strict typed transport, coherent direction, unique packet IDs and the independent source predicate.",
                "Bounded instance-owned UTC correlation state; no live producer or replay quality claimed."
            },
            NegativeConditions = new[]
            {
                "Missing or contradictory fields, duplicate IDs, reverse-time events and expired evidence fail closed.",
                "No inferred local file, identity, configuration, credential, success or compromise event."
            },
            FalsePositives = new[]
            {
                "Authorized administration, CI/CD, diagnostics, inventory and software upgrades may show these network patterns."
            },
            MinimumConfidence = 80,
            WindowThreshold = 3,
            Window = TimeSpan.FromSeconds(30),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "R824_ping_icmp_distinct_external_targets",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] {
                "positive/benign", "missing/contradictory fields", "replay/reverse/expiry",
                "cooldown", "evidence privacy", "Candidate Shadow", "independent registry identity"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research706DistinctWindow _distinct = new();

        public R824_PingProcessPublicIcmpTargetFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (r == null || r.Id == Guid.Empty || r.IpVersion != 4
                || r.IsTcp || r.IsUdp || r.IsQuic
                || !string.Equals(r.Protocol, "ICMP", StringComparison.OrdinalIgnoreCase)
                || r.SourcePort != null || r.DestinationPort != null || r.TcpFlags != null
                || r.IcmpTypeCode != 0x0800 || r.L4Len is null or < 8 or > 256
                || r.Length < r.L4Len.Value + 20
                || !Research786NetworkEvidence.PrivatePublic(r)
                || !Research676Evidence.Process(r, "ping", "ping.exe")
                || !_distinct.Observe(r.Source! + "|" + r.ProcessId,
                    r.Destination!, r.Id, context.TimestampUtc, 3, 30))
                return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2857", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "r824_ping_icmp_distinct_external_targets", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_causality_authorization_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "ping-attributed ICMP echo to three distinct public hosts observed; source attribution, authorization and outcome unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "typed_packet_or_process_fields");
                    confidence.AddEvidence(0.33, "independent_workbook_source_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_correlation");
                },
                count: 3, windowSeconds: 30);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
