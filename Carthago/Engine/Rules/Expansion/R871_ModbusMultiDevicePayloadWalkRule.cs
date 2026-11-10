// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero tests/builds executed. workbook.R2692.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R871_ModbusMultiDevicePayloadWalkRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R871", Name: "Private Modbus TCP payloads across four devices", Category: "Discovery",
            Description: "A modpoll-attributed private client sends similarly sized TCP data to four distinct private TCP/502 hosts in one /24 within 60s; read function, asset identity and collection outcome are unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R871.Enabled",
            EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R871", Name = "Private Modbus TCP payloads across four devices", Category = "Discovery",
            Description = "workbook.R2692: A modpoll-attributed private client sends similarly sized TCP data to four distinct private TCP/502 hosts in one /24 within 60s; read function, asset identity and collection outcome are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "destination.port", "packet.id", "process.id" },
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
            Window = TimeSpan.FromSeconds(60), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "modpoll_four_distinct_private_modbus_targets",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive and benign typed cases", "missing and contradictory fields",
                "duplicate IDs, reverse time, window expiry", "cooldown recovery",
                "raw Info exclusion", "neighbor independence", "Candidate Shadow registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research706DistinctWindow _distinct = new();
        public R871_ModbusMultiDevicePayloadWalkRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.Internal(r)
                || r.DestinationPort != 502 || r.L4Len is < 80 or > 240
                || !Research676Evidence.Process(r, "modpoll", "modpoll.exe")
                || r.HttpMethod != null || r.HttpUri != null || r.TlsVersion != null
                || r.Sni != null || r.DnsQname != null) return NoMatch();
            var key = r.Source! + "|" + Research786NetworkEvidence.Subnet24(r.Destination!) + "|" + r.ProcessId;
            if (!_distinct.Observe(key, r.Destination!, r.Id, context.TimestampUtc, 4, 60)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2692", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "modpoll_four_distinct_private_modbus_targets", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_shape_only_causality_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Private Modbus TCP payloads across four devices; producer provenance, authorization and security outcome unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 4, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

