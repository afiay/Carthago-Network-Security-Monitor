// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero tests/builds executed. workbook.R1834.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R883_VmwareVmxPublicTlsPeerFanoutRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R883", Name: "VMware VMX-attributed TLS/8443 to three public peers", Category: "CommandAndControl",
            Description: "VMware VMX-attributed TCP payload with TLS metadata on 8443 reaches three distinct public IPs with one SNI within 90s; VM identity, allowlist status, encrypted content and C2 are unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R883.Enabled",
            EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R883", Name = "VMware VMX-attributed TLS/8443 to three public peers", Category = "CommandAndControl",
            Description = "workbook.R1834: VMware VMX-attributed TCP payload with TLS metadata on 8443 reaches three distinct public IPs with one SNI within 90s; VM identity, allowlist status, encrypted content and C2 are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Tls },
            RequiredFields = new[] { "process.id", "tls.sni", "tls.version", "destination", "destination.port", "packet.id" },
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
            MinimumConfidence = 80, WindowThreshold = 3,
            Window = TimeSpan.FromSeconds(90), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "vmware_vmx_tls8443_three_distinct_public_peers",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near-miss cases",
                "missing or contradictory transport", "duplicate and reverse UTC / expired window",
                "cooldown recovery", "raw Info exclusion", "neighbor independence",
                "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research706DistinctWindow _distinct = new();
        public R883_VmwareVmxPublicTlsPeerFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || !Research676Evidence.Process(r, "vmware-vmx", "vmware-vmx.exe")
                || r.DestinationPort != 8443 || r.L4Len is < 600 or > 1000
                || string.IsNullOrWhiteSpace(r.TlsVersion)
                || string.IsNullOrWhiteSpace(r.Sni) || r.Sni.Length > 253
                || r.HttpMethod != null || r.HttpUri != null || r.DnsQname != null
                || !_distinct.Observe(r.Source! + "|" + r.ProcessId + "|" + r.Sni.ToLowerInvariant(),
                    r.Destination!, r.Id, context.TimestampUtc, 3, 90))
                return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1834", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "vmware_vmx_tls8443_three_distinct_public_peers", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_shape_only_causality_authorization_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "VMware VMX-attributed TLS/8443 to three public peers; producer provenance, authorization, causality and outcome unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 3, windowSeconds: 90);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

