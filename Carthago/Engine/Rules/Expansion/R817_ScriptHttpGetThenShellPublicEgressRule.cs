// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit source authored first, 0 tests executed; workbook.R1475.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R817_ScriptHttpGetThenShellPublicEgressRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R817",
            Name: "curl script URL GET then shell-attributed different-peer TLS payload",
            Category: "Execution",
            Description: "curl script URL GET then shell-attributed different-peer TLS payload. Source-only network/process evidence; no authorization, compromise or successful outcome inferred.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R817.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R817",
            Name = "curl script URL GET then shell-attributed different-peer TLS payload",
            Category = "Execution",
            Description = "workbook.R1475: No filesystem write, chmod, execution lineage, script content or malicious content injection is visible.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id", "destination.port" },
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
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(90),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "R817_script_http_get_then_shell_tls_other_peer",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] {
                "positive/benign", "missing/contradictory fields", "replay/reverse/expiry",
                "cooldown", "evidence privacy", "Candidate Shadow", "independent registry identity"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research806DifferentPeerWindow _peers = new();

        public R817_ScriptHttpGetThenShellPublicEgressRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r))
                return NoMatch();
            if (r.DestinationPort == 80 && Research676Evidence.Process(r, "curl", "curl.exe", "wget", "wget.exe")
                && WebSignatureRequestEvidence.TryGet(r, out var method, out var uri) && method == "GET"
                && (uri.EndsWith(".sh", StringComparison.OrdinalIgnoreCase)
                    || uri.EndsWith(".bash", StringComparison.OrdinalIgnoreCase)))
            {
                _peers.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc, true);
                return NoMatch();
            }
            if (r.DestinationPort != 8443
                || !Research676Evidence.Process(r, "bash", "sh")
                || r.L4Len is < 128 or > 4096
                || string.IsNullOrWhiteSpace(r.TlsVersion) || string.IsNullOrWhiteSpace(r.Sni)
                || r.HttpMethod != null || r.DnsQname != null
                || !_peers.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc, false))
                return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1475", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "r817_script_http_get_then_shell_tls_other_peer", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_causality_authorization_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "curl script URL GET then shell-attributed different-peer TLS payload observed; source attribution, authorization and outcome unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "typed_packet_or_process_fields");
                    confidence.AddEvidence(0.33, "independent_workbook_source_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_correlation");
                },
                count: 2, windowSeconds: 90);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
