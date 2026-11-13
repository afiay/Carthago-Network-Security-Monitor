// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2744 / AN1249.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R971_PublicSnmpHighDemandGetBulkRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R971", Name: "Public SNMP high-demand GETBULK request", Category: "IotOtAdvanced",
            Description: "Public IPv4 source sends a capture-validated SNMPv2c GETBULK request with 64–1024 max-repetitions, zero non-repeaters and one to eight valid OIDs to private UDP/161. Authorization and returned data unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R971.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R971", Name = "Public SNMP high-demand GETBULK request", Category = "IotOtAdvanced",
            Description = "workbook.R2744 AN1249: exact high-demand GETBULK operation, distinct from R771 packet-count burst; no MIB dump completion or authenticated access inferred.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "destination.port", "packet.id", "snmp.high_demand_getbulk.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Complete IPv4 UDP/161 SNMPv2c GETBULK with canonical positive max-repetitions 64–1024, zero non-repeaters, 1–8 valid OID/NULL bindings." },
            NegativeConditions = new[] { "GET/GETNEXT/SET/response, low or out-of-policy demand, invalid OID/value/BER, other versions, incomplete datagram and contradictory/missing evidence fail closed." },
            FalsePositives = new[] { "Authorized inventory, managed-service polling and bulk diagnostics can request this amount; threshold is a candidate heuristic, not a calibrated anomaly." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "public_private_snmp_high_demand_getbulk",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "raw capture positives and exact numeric bounds", "ordinary read and other PDU controls", "malformed BER/OID/value and count bounds",
                "scope, truncation, contradictory and forged evidence", "duplicate/reverse UTC/cooldown and peer isolation", "R771 non-convergence, privacy and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R971_PublicSnmpHighDemandGetBulkRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.UdpData(r) || !Research786NetworkEvidence.PublicPrivate(r) ||
                r.DestinationPort != 161 || r.SourcePort == 161 || r.L4Len is not (>= 20 and <= 4096) ||
                !r.SnmpHighDemandGetBulkObserved || r.SnmpEnterpriseSetRequestObserved || r.SnmpUpsRebootRequestObserved ||
                r.ApplicationProtocol != "snmp.getbulk.high_demand.request" ||
                r.DnsQname != null || r.DnsIsResponse || r.HttpUri != null || r.HttpMethod != null ||
                r.TlsVersion != null || r.Sni != null) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2744", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "capture_decoded_external_high_demand_getbulk", "rule"),
                new DetectionEvidenceItem("outcome", "request_only_authorization_and_returned_data_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "External SNMP high-demand GETBULK request observed; authorization and returned MIB data unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_high_demand_getbulk_structure");
                    confidence.AddEvidence(0.35, "public_to_private_management_boundary");
                }, count: 1, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
