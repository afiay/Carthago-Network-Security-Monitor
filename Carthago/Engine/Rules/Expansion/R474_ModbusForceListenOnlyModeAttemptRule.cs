// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R474_ModbusForceListenOnlyModeAttemptRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R474_ModbusForceListenOnlyModeAttemptRule : OtIcsDeepPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R474",
            Name: "Modbus Force Listen Only Mode Attempt",
            Category: "OtIcsDeep",
            Description: "Identifies a complete, capture-verified first Modbus/TCP diagnostics FC08 subfunction 0x0004 request on a SYN-anchored plaintext flow. Attempt only; no device-state change or authorization is asserted.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R474.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R474",
            Name = "Modbus Force Listen Only Mode Attempt",
            Category = "OtIcsDeep",
            Description = "Detects Modbus Force Listen Only Mode Attempt only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Critical,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "protocol_or_port" },
            EvidenceFields = new[] { "capture.provenance", "ot.protocol", "function.code", "matched_conditions" },
            PositiveConditions = new[] { "Capture-bound first client request must be a complete Modbus/TCP MBAP frame with FC08, subfunction 0x0004 and zero data.", "Observed client SYN and matching server SYN-ACK, exact TCP sequence/ack, plaintext and no packet fragmentation are required.", "Only a request attempt is supported; no controller state change or malicious actor is inferred." },
            NegativeConditions = new[] { "Reject port-only, process-label, Info-only or imported traffic records; require capture-owned typed producer.", "Reject malformed MBAP, other diagnostics subfunctions, wrong direction, wrong ACK, late, second or partial payload.", "Authorized engineering and gateway operation may legitimately use diagnostics; keep in Shadow." },
            FalsePositives = new[] { "Engineering workstations, PLC programming sessions, historian jobs, and approved vendor maintenance can produce these commands; require approved-source tuning." },
            TextIndicators = new[] { "modbus force listen only mode attempt", "modbus", "force", "listen", "only", "mode", "s7", "dnp3", "opc", "bacnet", "profinet", "goose", "mms", "write", "control", "function" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "read device identification", "write property", "devicecommunicationcontrol" },
            ProcessIndicators = new[] { "tia", "step7", "plc", "codesys", "modbuspoll", "opcua", "engineering", "hmi", "scada" },
            ProtocolIndicators = new[] { "modbus" },
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 502 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 86,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(10),
            Cooldown = TimeSpan.FromMinutes(45),
            DistinctBy = "source+destination+oticsdeep+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedEngineeringWorkstations", "ApprovedVendorJumpHosts", "CriticalAssetRanges", "CommandThreshold" },
            RequiredTests = new[] { "positive R474 evidence-gated sample", "negative R474 descriptor-only sample", "negative R474 missing telemetry sample", "negative R474 approved-admin sample" },
            RequireCrossBoundary = false,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R474_ModbusForceListenOnlyModeAttemptRule() : base(Rule, Profile) { }

        private readonly WebSignatureCooldown _cooldown = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!r.ModbusForceListenOnlyModeAttemptObserved || r.Id == Guid.Empty ||
                context.TimestampUtc.Kind != DateTimeKind.Utc || !r.IsTcp || r.IsUdp ||
                r.IpVersion != 4 || r.DestinationPort != 502 ||
                r.SourcePort is not int sourcePort || sourcePort <= 0 || sourcePort == 502 ||
                string.IsNullOrWhiteSpace(r.Source) || string.IsNullOrWhiteSpace(r.Destination) ||
                !string.Equals(r.ApplicationProtocol, "modbus.tcp.force_listen_only.attempt", StringComparison.Ordinal))
                return NoMatch();

            var cooldown = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (cooldown == WebSignatureObservation.None) return NoMatch();
            if (cooldown == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evt = CreateDetectionEvent(context, SeverityLevel.Critical,
                "Captured a Modbus diagnostics Force Listen Only Mode request attempt (FC08/subfunction 0x0004); device state, authorization and outcome unverified.",
                new[]
                {
                    new DetectionEvidenceItem("capture.provenance", "first_syn_synack_anchored_complete_tcp_request", "packet-handler"),
                    new DetectionEvidenceItem("ot.protocol", "modbus_tcp", "wire"),
                    new DetectionEvidenceItem("function.code", "08:0004", "wire"),
                    new DetectionEvidenceItem("matched_conditions", "force_listen_only_attempt_only_no_success_inferred", "rule")
                },
                confidence =>
                {
                    confidence.AddEvidence(0.48, "complete_wire_exact_modbus_request");
                    confidence.AddEvidence(0.30, "verified_client_syn_ack_and_mbap");
                    confidence.AddCorrelation(0.15, "bounded_first_request_provenance");
                }, count: 1, windowSeconds: 0);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
