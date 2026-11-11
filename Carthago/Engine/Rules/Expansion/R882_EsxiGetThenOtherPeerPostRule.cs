// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero tests/builds executed. workbook.R1831.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R882_EsxiGetThenOtherPeerPostRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R882", Name: "ESXi utility public script GET then other-peer HTTP check-in POST", Category: "CommandAndControl",
            Description: "esxcli-attributed public HTTP GET for a .sh path precedes busybox-attributed HTTP check-in POST to a different public IP from the same private host within 60s; no process lineage, execution or C2 proved.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R882.Enabled",
            EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R882", Name = "ESXi utility public script GET then other-peer HTTP check-in POST", Category = "CommandAndControl",
            Description = "workbook.R1831: esxcli-attributed public HTTP GET for a .sh path precedes busybox-attributed HTTP check-in POST to a different public IP from the same private host within 60s; no process lineage, execution or C2 proved.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Process },
            RequiredFields = new[] { "process.id", "http.method", "http.uri", "source", "destination", "packet.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Coherent typed IPv4 transport fields and independent observable source predicate.",
                "Bounded per-rule monotonic UTC observation, with no unavailable producer asserted."
            },
            NegativeConditions = new[]
            {
                "Missing, contradictory, duplicate, out-of-order or expired evidence fails closed.",
                "No authenticated identity, file transfer, decoded encrypted content, command execution, configuration or outcome inferred."
            },
            FalsePositives = new[]
            {
                "Approved maintenance, software deployment, diagnostics, administrative sessions and normal traffic may share this shape."
            },
            MinimumConfidence = 80, WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(60), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "esxcli_public_sh_get_then_busybox_different_peer_checkin_post",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near-miss cases",
                "missing or contradictory transport", "duplicate and reverse UTC / expired window",
                "cooldown recovery", "raw Info exclusion", "neighbor independence",
                "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research806DifferentPeerWindow _different = new();
        public R882_EsxiGetThenOtherPeerPostRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || r.DestinationPort != 80
                || !WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                || string.IsNullOrWhiteSpace(r.HttpHost) || r.HttpHost.Length > 253) return NoMatch();
            var first = Research676Evidence.Process(r, "esxcli")
                && method == "GET" && uri.StartsWith("/download/", StringComparison.OrdinalIgnoreCase)
                && uri.EndsWith(".sh", StringComparison.OrdinalIgnoreCase);
            var second = Research676Evidence.Process(r, "busybox", "busybox.exe")
                && method == "POST" && uri == "/api/checkin";
            if (!first && !second) return NoMatch();
            if (!_different.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc, first))
                return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1831", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "esxcli_public_sh_get_then_busybox_different_peer_checkin_post", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_shape_only_causality_authorization_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "ESXi utility public script GET then other-peer HTTP check-in POST; producer provenance, authorization, causality and outcome unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 2, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

