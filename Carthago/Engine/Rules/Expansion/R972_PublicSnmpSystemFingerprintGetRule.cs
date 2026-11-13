// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2771 / AN2186.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R972_PublicSnmpSystemFingerprintGetRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R972", Name: "Public SNMP system fingerprint GET request", Category: "IotOtAdvanced",
            Description: "Public IPv4 source sends a capture-validated SNMPv1/v2c GET containing exactly sysDescr.0, sysObjectID.0 and sysName.0 to private UDP/161. Authorization and returned data unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R972.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R972", Name = "Public SNMP system fingerprint GET request", Category = "IotOtAdvanced",
            Description = "workbook.R2771 AN2186: exact three distinct RFC3418 system scalar GET bindings; not proof of OT device role, unauthorized discovery or a returned fingerprint.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "destination.port", "packet.id", "snmp.system_fingerprint_get.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Complete IPv4 UDP/161 SNMPv1/v2c GET; exactly one of each sysDescr.0, sysObjectID.0, sysName.0, with empty NULL values and zero error/index." },
            NegativeConditions = new[] { "Single/two-object health polling, duplicate/missing/extra/wrong scalar, GETNEXT/GETBULK/SET/response, malformed BER, incomplete or contradictory capture and wrong scope fail closed." },
            FalsePositives = new[] { "Authorized external NMS, inventory, managed-service discovery and troubleshooting may request the same three scalars." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "public_private_snmp_exact_system_fingerprint_get",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "raw capture v1/v2c and binding permutation", "single/two-object and adjacent OID benign controls", "duplicate/extra/malformed BER and PDU controls",
                "scope, datagram integrity and forged/contradictory evidence", "duplicate/reverse UTC/cooldown and peer isolation", "R966/R969/R971 non-convergence, privacy and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R972_PublicSnmpSystemFingerprintGetRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.UdpData(r) || !Research786NetworkEvidence.PublicPrivate(r) ||
                r.DestinationPort != 161 || r.SourcePort == 161 || r.L4Len is not (>= 20 and <= 4096) ||
                !r.SnmpSystemFingerprintGetObserved || r.SnmpEnterpriseSetRequestObserved ||
                r.SnmpUpsRebootRequestObserved || r.SnmpHighDemandGetBulkObserved ||
                r.ApplicationProtocol != "snmp.get.system_fingerprint.request" ||
                r.DnsQname != null || r.DnsIsResponse || r.HttpUri != null || r.HttpMethod != null ||
                r.TlsVersion != null || r.Sni != null) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2771", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "capture_decoded_external_exact_system_fingerprint_get", "rule"),
                new DetectionEvidenceItem("outcome", "request_only_authorization_and_returned_data_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "External SNMP system fingerprint GET request observed; device role, authorization and returned values unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_exact_system_fingerprint_get");
                    confidence.AddEvidence(0.35, "public_to_private_management_boundary");
                }, count: 1, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
