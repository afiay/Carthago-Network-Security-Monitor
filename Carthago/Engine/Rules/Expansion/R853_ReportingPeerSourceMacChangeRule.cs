// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; no tests or builds executed. workbook.R2702.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R853_ReportingPeerSourceMacChangeRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R853", Name: "One internal telemetry peer sends TCP/1883 with two source MACs", Category: "Industrial",
            Description: "Two coherent same-endpoint internal TCP/1883 reporting payload packets carry distinct canonical Ethernet source MACs within 60s; no enrolled identity, message spoof or physical process divergence established.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R853.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R853", Name = "One internal telemetry peer sends TCP/1883 with two source MACs", Category = "Industrial",
            Description = "workbook.R2702: Two coherent same-endpoint internal TCP/1883 reporting payload packets carry distinct canonical Ethernet source MACs within 60s; no enrolled identity, message spoof or physical process divergence established.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "packet.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] {
                "Coherent typed IPv4 packet predicate, unique identifiers and rule-owned bounded UTC observation.",
                "Only locally observed process or transport fields; no remote security outcome asserted."
            },
            NegativeConditions = new[] {
                "Missing/contradictory typed fields, duplicate IDs, reverse UTC time and stale state fail closed.",
                "No terminal login, decrypted content, file write, interface proof, authorization or actor inferred."
            },
            FalsePositives = new[] {
                "Administration, diagnostics, updates, sensor attribution errors and authorized security tests may share the observable pattern."
            },
            MinimumConfidence = 80, WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(60), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "internal_1883_reporting_source_mac_change",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] {
                "source-specific positive/benign cases", "missing and contradictory evidence",
                "duplicate, reverse and expiry", "cooldown recovery", "raw Info excluded",
                "neighboring rule non-convergence", "Candidate Shadow registration"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research706DistinctWindow _macs = new();
        public R853_ReportingPeerSourceMacChangeRule() : base(Rule, Profile) { }
        private static bool CanonicalMac(string? mac)
        {
            if (mac == null || mac.Length != 17) return false;
            for (var i = 0; i < mac.Length; i++)
            {
                if (i is 2 or 5 or 8 or 11 or 14)
                {
                    if (mac[i] != ':') return false;
                }
                else if (!Uri.IsHexDigit(mac[i])) return false;
            }
            return true;
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.Internal(r)
                || r.DestinationPort != 1883 || r.L4Len is < 128 or > 4096
                || r.HttpMethod != null || r.DnsQname != null || r.TlsVersion != null
                || !CanonicalMac(r.MacSource)) return NoMatch();
            var key = r.Source! + "|" + r.Destination! + "|" + r.DestinationPort;
            if (!_macs.Observe(key, r.MacSource!.ToLowerInvariant(), r.Id, context.TimestampUtc, 2, 60)) return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[] {
                new DetectionEvidenceItem("research.identifier", "workbook.R2702", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "internal_1883_reporting_source_mac_change", "rule"),
                new DetectionEvidenceItem("outcome", "typed_observation_only_attribution_and_security_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "One internal telemetry peer sends TCP/1883 with two source MACs observed; process provenance, authorization, causality and outcome unknown.",
                evidence, confidence => {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_signal");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 2, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

