// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero tests/builds executed. workbook.R2772.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R873_SsdpMulticastThenDeviceHttpSynRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R873", Name: "SSDP-port multicast then private HTTP device SYN", Category: "Discovery",
            Description: "Private source sends UDP/1900 to SSDP multicast then TCP SYN to another private device's 8008 within 60s; no decoded M-SEARCH, IGMP join or discovered service verified.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R873.Enabled",
            EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R873", Name = "SSDP-port multicast then private HTTP device SYN", Category = "Discovery",
            Description = "workbook.R2772: Private source sends UDP/1900 to SSDP multicast then TCP SYN to another private device's 8008 within 60s; no decoded M-SEARCH, IGMP join or discovered service verified.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "destination.port", "protocol", "packet.id" },
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
            MinimumConfidence = 80, WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(60), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "ssdp_multicast_udp1900_then_private_tcp8008_syn",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive and benign typed cases", "missing and contradictory fields",
                "duplicate IDs, reverse time, window expiry", "cooldown recovery",
                "raw Info exclusion", "neighbor independence", "Candidate Shadow registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R873_SsdpMulticastThenDeviceHttpSynRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            if (Research786NetworkEvidence.UdpData(r)
                && string.Equals(r.Destination, "239.255.255.250", StringComparison.Ordinal)
                && r.DestinationPort == 1900 && r.L4Len is >= 100 and <= 350
                && IPAddress.TryParse(r.Source, out var privateSource) && Research646Evidence.Private(privateSource)
                && r.ApplicationProtocol == null && r.HttpMethod == null && r.HttpUri == null
                && r.DnsQname == null && r.TlsVersion == null && r.Sni == null)
            {
                _stages.Observe(r.Source!, r.Id, context.TimestampUtc, true, 60);
                return NoMatch();
            }
            if (!Research676Evidence.Syn(r) || !Research786NetworkEvidence.Internal(r)
                || r.DestinationPort != 8008
                || !_stages.Observe(r.Source!, r.Id, context.TimestampUtc, false, 60)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2772", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "ssdp_multicast_udp1900_then_private_tcp8008_syn", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_shape_only_causality_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "SSDP-port multicast then private HTTP device SYN; producer provenance, authorization and security outcome unverified.",
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

