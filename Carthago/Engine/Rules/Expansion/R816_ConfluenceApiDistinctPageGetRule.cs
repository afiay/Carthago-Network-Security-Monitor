// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit source authored first, 0 tests executed; workbook.R2838.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R816_ConfluenceApiDistinctPageGetRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R816",
            Name: "curl-attributed distinct Confluence-style page API GET burst",
            Category: "Collection",
            Description: "curl-attributed distinct Confluence-style page API GET burst. Source-only network/process evidence; no authorization, compromise or successful outcome inferred.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R816.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R816",
            Name = "curl-attributed distinct Confluence-style page API GET burst",
            Category = "Collection",
            Description = "workbook.R2838: No SaaS identity, role, page sensitivity, content read success or excessive access baseline is known.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id", "http.uri", "http.host" },
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
            WindowThreshold = 4,
            Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "R816_confluence_style_distinct_page_get",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] {
                "positive/benign", "missing/contradictory fields", "replay/reverse/expiry",
                "cooldown", "evidence privacy", "Candidate Shadow", "independent registry identity"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research706DistinctWindow _distinct = new();

        public R816_ConfluenceApiDistinctPageGetRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || !Research676Evidence.Process(r, "curl", "curl.exe")
                || r.DestinationPort != 80 || !WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                || method != "GET" || !uri.StartsWith("/rest/api/content/", StringComparison.OrdinalIgnoreCase)
                || uri.Length <= "/rest/api/content/".Length
                || string.IsNullOrWhiteSpace(r.HttpHost) || r.HttpHost.Length > 253
                || !r.HttpHost.Contains("confluence", StringComparison.OrdinalIgnoreCase)
                || !_distinct.Observe(r.Source! + "|" + r.ProcessId + "|" + r.Destination
                    + "|" + r.HttpHost.ToLowerInvariant(), uri.ToLowerInvariant(), r.Id,
                    context.TimestampUtc, 4, 60))
                return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2838", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "r816_confluence_style_distinct_page_get", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_causality_authorization_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "curl-attributed distinct Confluence-style page API GET burst observed; source attribution, authorization and outcome unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "typed_packet_or_process_fields");
                    confidence.AddEvidence(0.33, "independent_workbook_source_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_correlation");
                },
                count: 4, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
