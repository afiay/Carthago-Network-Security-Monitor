// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2708 / AN2212.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R970_PublicIec104StartupOffExecuteRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R970", Name: "Public IEC104 startup followed by double-command OFF execution", Category: "IotOtAdvanced",
            Description: "Public IPv4 TCP/2404 client sends an exact IEC104 double-command OFF execute request after observed STARTDT activation/confirmation. Asset role, approval and physical outcome unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R970.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R970", Name = "Public IEC104 startup followed by double-command OFF execution", Category = "IotOtAdvanced",
            Description = "workbook.R2708 AN2212: capture-qualified startup and first C_DC_NA_1 OFF execute request; no breaker identity, approval or successful outcome inferred.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "destination.port", "packet.id", "iec104.startup_off_execute.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Complete same-flow SYN/SYN-ACK, STARTDT act/con and first exact I-format type 46 OFF execute, all sequence-contiguous and within 30 seconds." },
            NegativeConditions = new[] { "Missing or cross-flow confirmation, ON/select, test/negative flags, unsupported cause/type/address, malformed/coalesced APDU, gap/retransmit, expiry and wrong scope fail closed." },
            FalsePositives = new[] { "Authorized remote SCADA switching, commissioning, power-system tests or recovery can issue identical commands." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(30),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "public_private_iec104_startup_off_execute",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "capture sequence positive", "ON/select/control/format negatives", "missing or cross-flow startup confirmation",
                "TCP integrity, reuse, expiry and scope", "privacy, duplicate/cooldown, peer isolation and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R970_PublicIec104StartupOffExecuteRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PublicPrivate(r) ||
                r.DestinationPort != 2404 || r.SourcePort == 2404 || r.L4Len != 16 ||
                !r.Iec104StartupOffExecuteObserved ||
                r.DnsQname != null || r.DnsIsResponse || r.HttpUri != null || r.HttpMethod != null ||
                r.TlsVersion != null || r.Sni != null) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2708", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "capture_decoded_iec104_startdt_then_off_execute", "rule"),
                new DetectionEvidenceItem("outcome", "request_only_asset_role_approval_and_physical_effect_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "External IEC104 startup followed by double-command OFF execute observed; asset role, authorization and physical effect unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_iec104_startup_and_off_execute");
                    confidence.AddEvidence(0.35, "public_to_private_control_boundary");
                }, count: 1, windowSeconds: 30);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
