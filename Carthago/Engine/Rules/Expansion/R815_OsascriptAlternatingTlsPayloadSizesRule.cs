// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit source authored, 0 tests executed; workbook.R2833.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R815_OsascriptAlternatingTlsPayloadSizesRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R815",
            Name: "osascript attributed alternating short and long external TLS packets",
            Category: "EvasionTunnel",
            Description: "osascript attributed alternating short and long external TLS packets. Observable packet/process shape only; no authorization, causality, success or compromise inferred.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R815.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R815",
            Name = "osascript attributed alternating short and long external TLS packets",
            Category = "EvasionTunnel",
            Description = "workbook.R2833: Alternating packet sizes do not prove obfuscation, long-lived sessions or C2; four monotonic, bounded observations only.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Tls, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id", "tls.sni", "l4.length", "destination.port" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Typed and mutually coherent transport/direction fields plus the narrow independent predicate.",
                "Bounded instance-owned monotonic UTC state and distinct packet provenance; not live validation."
            },
            NegativeConditions = new[]
            {
                "Incomplete/contradictory process, protocol, port, peer or context, duplicate IDs and stale time fail closed.",
                "No free-form Info assertion, secret, raw payload, endpoint audit, authorization or success claim."
            },
            FalsePositives = new[]
            {
                "Approved operations, maintenance, diagnostics and scripted administration can produce similar traffic."
            },
            MinimumConfidence = 80,
            WindowThreshold = 4,
            Window = TimeSpan.FromSeconds(90),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "R815_osascript_short_long_tls_size_alternation",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive/benign", "missing/contradictory telemetry", "duplicate/reverse/expiry",
                "cooldown recovery", "privacy", "Candidate Shadow", "independence/registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research806AlternatingSizeWindow _alternation = new();

        public R815_OsascriptAlternatingTlsPayloadSizesRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || !Research676Evidence.Process(r, "osascript")
                || r.DestinationPort != 443 || string.IsNullOrWhiteSpace(r.Sni)
                || string.IsNullOrWhiteSpace(r.TlsVersion) || r.Sni.Length > 253
                || r.HttpMethod != null || r.DnsQname != null
                || !_alternation.Observe(r.Source! + "|" + r.ProcessId + "|" + r.Destination
                    + "|" + r.Sni.ToLowerInvariant(), r.Id, r.L4Len!.Value, context.TimestampUtc))
                return NoMatch();

            var observation = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (observation == WebSignatureObservation.None) return NoMatch();
            if (observation == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2833", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "r815_osascript_short_long_tls_size_alternation", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_impact_causality_and_authorization_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "osascript attributed alternating short and long external TLS packets observed; asset role, causal context and outcome unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "typed_packet_or_local_process_evidence");
                    confidence.AddEvidence(0.33, "independent_workbook_sourced_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_packet_correlation");
                },
                count: 4, windowSeconds: 90);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
