// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2714 / AN1908.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R982_PublicModbusClearMaskWriteRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R982", Name: "Public Modbus all-zero mask register write request", Category: "IotOtAdvanced",
            Description: "Public IPv4 client sends a capture-validated first Modbus TCP FC22 Mask Write Register request with both masks zero to private TCP/502. Authorization, register semantics and write outcome unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R982.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R982", Name = "Public Modbus all-zero mask register write request", Category = "IotOtAdvanced",
            Description = "workbook.R2714 AN1908: exact clear-all mask request; not proof of unsafe parameter or historian drift.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "destination.port", "packet.id", "modbus.clear_mask_write.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Complete IPv4 TCP/502 SYN-anchored first contiguous client PSH/ACK payload, exact MBAP protocol 0 length 8 unit 1–247, FC22, AND=0 OR=0." },
            NegativeConditions = new[] { "Other functions, nonzero masks, wrong MBAP/unit/length, partial/coalesced payload, midstream/response/retransmission, TLS, wrong scope and contradictory fields fail closed." },
            FalsePositives = new[] { "Authorized maintenance, initialization, reset and recovery may deliberately clear a register. No unsafe value, device semantics or historian drift inferred." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "public_private_modbus_clear_mask_write",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "raw capture transaction/unit/register bounds", "ordinary mask/other function and malformed framing controls",
                "midstream, retransmit, response, fragmentation and scope", "forgery/contradictions and adjacent rule separation",
                "duplicate/reverse time/cooldown, peer isolation, privacy and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R982_PublicModbusClearMaskWriteRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PublicPrivate(r) ||
                r.DestinationPort != 502 || r.SourcePort == 502 || r.L4Len != 14 ||
                !r.ModbusClearMaskWriteObserved || r.ModbusSingleRegisterWritePoint.HasValue ||
                r.ModbusOversizedReadExceptionObserved || r.ModbusBulkFileReadResponseObserved ||
                r.DnsQname != null || r.DnsIsResponse || r.HttpUri != null || r.HttpMethod != null ||
                r.TlsVersion != null || r.Sni != null) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2714", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "capture_decoded_external_modbus_fc22_both_masks_zero", "rule"),
                new DetectionEvidenceItem("outcome", "request_only_authorization_register_semantics_and_effect_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "External Modbus mask-write request with both masks zero observed; register semantics, authorization and outcome unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_modbus_mask_write_request");
                    confidence.AddEvidence(0.35, "public_to_private_control_boundary");
                }, count: 1, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
