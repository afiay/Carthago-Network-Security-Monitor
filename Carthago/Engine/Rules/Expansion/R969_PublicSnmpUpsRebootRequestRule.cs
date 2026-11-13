// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2768, AN2187.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R969_PublicSnmpUpsRebootRequestRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R969", Name: "Public SNMP UPS reboot-duration SET request", Category: "IotOtAdvanced",
            Description: "Public IPv4 source sends a complete SNMPv1/v2c SET for UPS-MIB upsRebootWithDuration.0 with a valid nonnegative Integer32 duration to private UDP/161. Request only; authorization and UPS reboot are unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R969.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R969", Name = "Public SNMP UPS reboot-duration SET request", Category = "IotOtAdvanced",
            Description = "workbook.R2768 AN2187: exact RFC1628 UPS reboot scalar SET, not arbitrary SNMP enterprise management or successful restart.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "destination.port", "packet.id", "snmp.ups_reboot.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Complete capture-validated IPv4 UDP/161 SNMPv1/v2c SET; exact single UPS reboot scalar and nonnegative Integer32." },
            NegativeConditions = new[] { "Read, response, other scalar, enterprise OID, noncanonical or negative duration, multi-binding SET, wrong scope and missing capture evidence fail closed." },
            FalsePositives = new[] { "Authorized UPS maintenance, power tests or remote facility administration may issue this exact SET." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "public_private_ups_reboot_scalar_set",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "capture positive v1/v2c and duration limits", "benign polling and adjacent OID controls",
                "malformed BER, mixed and missing evidence", "scope and R966 independence", "duplicate/reverse UTC/cooldown/peer isolation", "privacy and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R969_PublicSnmpUpsRebootRequestRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.UdpData(r) || !Research786NetworkEvidence.PublicPrivate(r) ||
                r.DestinationPort != 161 || r.L4Len is not (>= 20 and <= 4096) ||
                !r.SnmpUpsRebootRequestObserved || r.SnmpEnterpriseSetRequestObserved ||
                r.ApplicationProtocol != "snmp.ups.reboot.request" ||
                r.DnsQname != null || r.DnsIsResponse || r.HttpUri != null || r.HttpMethod != null ||
                r.TlsVersion != null || r.Sni != null) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2768", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "capture_decoded_ups_reboot_scalar_set", "rule"),
                new DetectionEvidenceItem("outcome", "request_only_authorization_and_reboot_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "External SNMP UPS reboot-duration SET request observed; authorization and power-state change unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_exact_ups_reboot_request");
                    confidence.AddEvidence(0.35, "public_to_private_management_boundary");
                }, count: 1, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
