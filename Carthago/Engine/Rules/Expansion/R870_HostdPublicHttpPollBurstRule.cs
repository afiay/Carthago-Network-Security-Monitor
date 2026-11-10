// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero tests/builds executed. workbook.R2036.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R870_HostdPublicHttpPollBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R870", Name: "ESXi hostd-attributed repeated public HTTP GET polling", Category: "CommandAndControl",
            Description: "Four hostd-attributed GET requests to one public web-service polling URI within 40s; one-way C2, remote commands and ESXi role are not established.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R870.Enabled",
            EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R870", Name = "ESXi hostd-attributed repeated public HTTP GET polling", Category = "CommandAndControl",
            Description = "workbook.R2036: Four hostd-attributed GET requests to one public web-service polling URI within 40s; one-way C2, remote commands and ESXi role are not established.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Process },
            RequiredFields = new[] { "process.id", "http.method", "http.uri", "http.host", "source", "destination", "packet.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Coherent typed IPv4 transport fields and independent packet-observable predicate.",
                "Per-rule bounded monotonic UTC correlation; no missing producer claimed."
            },
            NegativeConditions = new[]
            {
                "Missing or contradictory fields, duplicate IDs, reversed time and expired windows fail closed.",
                "No trusted identity, host audit, changed configuration, authenticated action, exploit, C2 or impact inferred."
            },
            FalsePositives = new[]
            {
                "Authorized network administration, service discovery, maintenance and diagnostics may generate this shape."
            },
            MinimumConfidence = 80, WindowThreshold = 4,
            Window = TimeSpan.FromSeconds(40), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "hostd_public_api_poll_http_get_burst",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive and benign typed cases", "missing and contradictory fields",
                "duplicate IDs, reverse time, window expiry", "cooldown recovery",
                "raw Info exclusion", "neighbor independence", "Candidate Shadow registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research736CountWindow _burst = new();
        public R870_HostdPublicHttpPollBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || !Research676Evidence.Process(r, "hostd", "hostd.exe") || r.DestinationPort != 80
                || !WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                || method != "GET" || !uri.StartsWith("/api/", StringComparison.OrdinalIgnoreCase)
                || !uri.Contains("poll", StringComparison.OrdinalIgnoreCase)
                || string.IsNullOrWhiteSpace(r.HttpHost) || r.HttpHost.Length > 253
                || r.L4Len is < 350 or > 1600) return NoMatch();
            var key = r.Source! + "|" + r.Destination! + "|" + r.ProcessId + "|" + r.HttpHost.ToLowerInvariant() + "|" + uri.ToLowerInvariant();
            if (!_burst.Observe(key, r.Id, r.L4Len!.Value, context.TimestampUtc, 4, 40, 1400)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2036", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "hostd_public_api_poll_http_get_burst", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_shape_only_causality_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "ESXi hostd-attributed repeated public HTTP GET polling; producer provenance, authorization and security outcome unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 4, windowSeconds: 40);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

