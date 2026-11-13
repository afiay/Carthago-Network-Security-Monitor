// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2773, AN2183.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R966_PublicSnmpEnterpriseSetRequestRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R966", Name: "Public-source SNMP enterprise SET request", Category: "IotOtAdvanced",
            Description: "Public IPv4 source sends a capture-validated SNMPv1/v2c SET to a private device on UDP/161 with an enterprise OID. Authorization, vendor OID semantics and device modification are unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R966.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R966", Name = "Public-source SNMP enterprise SET request", Category = "IotOtAdvanced",
            Description = "workbook.R2773 AN2183: narrow capture-decoded enterprise SET observation; no approved-NMS inventory, undocumented OID, device role or successful change inferred.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "destination.port", "packet.id", "snmp.enterprise_set.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Complete IPv4 UDP/161 SNMPv1/v2c enterprise SET request from public to private peer." },
            NegativeConditions = new[] { "Read requests, responses, non-enterprise OIDs, unsupported values, malformed or partial BER, contradictory protocol or missing capture evidence fail closed." },
            FalsePositives = new[] { "Authorized managed-service or network administration may issue legitimate enterprise SET requests." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "public_source_private_peer_enterprise_set",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "raw capture positive and benign read control", "BER boundaries and malformed evidence", "scope and protocol contradictions",
                "duplicate and reverse UTC", "cooldown recovery and independent instances", "privacy and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R966_PublicSnmpEnterpriseSetRequestRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.UdpData(r) || !Research786NetworkEvidence.PublicPrivate(r) ||
                r.DestinationPort != 161 || r.L4Len is not (>= 20 and <= 4096) ||
                !r.SnmpEnterpriseSetRequestObserved || r.ApplicationProtocol != "snmp.enterprise.set.request" ||
                r.DnsQname != null || r.DnsIsResponse || r.HttpUri != null || r.HttpMethod != null ||
                r.TlsVersion != null || r.Sni != null) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2773", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "capture_decoded_external_enterprise_set", "rule"),
                new DetectionEvidenceItem("outcome", "request_only_authorization_and_device_change_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "External SNMP enterprise SET request observed; authorization and device change unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_snmp_request_structure");
                    confidence.AddEvidence(0.35, "public_to_private_management_boundary");
                }, count: 1, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
