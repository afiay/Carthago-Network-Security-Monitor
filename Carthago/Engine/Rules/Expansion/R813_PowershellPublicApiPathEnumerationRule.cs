// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit source authored, 0 tests executed; workbook.R1877.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R813_PowershellPublicApiPathEnumerationRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R813",
            Name: "PowerShell HTTP enumeration of four distinct external API resources",
            Category: "Collection",
            Description: "PowerShell HTTP enumeration of four distinct external API resources. Observable packet/process shape only; no authorization, causality, success or compromise inferred.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R813.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R813",
            Name = "PowerShell HTTP enumeration of four distinct external API resources",
            Category = "Collection",
            Description = "workbook.R1877: No local file reads, clipboard capture, or exfiltration are observed; distinct HTTP API GET paths only.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id", "http.uri", "http.host" },
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
            Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "R813_powershell_distinct_public_api_paths",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive/benign", "missing/contradictory telemetry", "duplicate/reverse/expiry",
                "cooldown recovery", "privacy", "Candidate Shadow", "independence/registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research706DistinctWindow _distinct = new();

        public R813_PowershellPublicApiPathEnumerationRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || !Research676Evidence.Process(r, "powershell", "powershell.exe", "pwsh", "pwsh.exe")
                || r.DestinationPort != 80 || !WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                || method != "GET" || !uri.StartsWith("/api/v1/resource/", StringComparison.OrdinalIgnoreCase)
                || uri.Length <= "/api/v1/resource/".Length || string.IsNullOrWhiteSpace(r.HttpHost)
                || r.HttpHost.Length > 253
                || !_distinct.Observe(r.Source! + "|" + r.ProcessId + "|" + r.Destination
                    + "|" + r.HttpHost.ToLowerInvariant(), uri.ToLowerInvariant(),
                    r.Id, context.TimestampUtc, 4, 60))
                return NoMatch();

            var observation = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (observation == WebSignatureObservation.None) return NoMatch();
            if (observation == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1877", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "r813_powershell_distinct_public_api_paths", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_impact_causality_and_authorization_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "PowerShell HTTP enumeration of four distinct external API resources observed; asset role, causal context and outcome unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "typed_packet_or_local_process_evidence");
                    confidence.AddEvidence(0.33, "independent_workbook_sourced_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_packet_correlation");
                },
                count: 4, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
