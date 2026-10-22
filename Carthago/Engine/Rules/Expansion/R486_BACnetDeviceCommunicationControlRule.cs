// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R486_BACnetDeviceCommunicationControlRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R486_BACnetDeviceCommunicationControlRule : OtIcsDeepPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R486",
            Name: "BACnet DeviceCommunicationControl",
            Category: "OtIcsDeep",
            Description: "Detects BACnet DeviceCommunicationControl only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R486.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R486",
            Name = "BACnet DeviceCommunicationControl",
            Category = "OtIcsDeep",
            Description = "Detects BACnet DeviceCommunicationControl only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Critical,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "ot_asset_destination", "ics_protocol_function" },
            EvidenceFields = new[] { "network.destinationPort", "ot.protocol", "function.code", "matched_conditions" },
            PositiveConditions = new[] { "BACnet DeviceCommunicationControl requires observable OtIcsDeep telemetry and will not match descriptor text alone.", "Source and destination, host, process, protocol, path, port, or payload evidence must be present.", "The configured signal count and time-window threshold must be satisfied before a DetectionEvent is emitted." },
            NegativeConditions = new[] { "Do not match on product names, rule names, documentation text, or generic banners alone.", "Do not match when source/destination context is absent or when the traffic is inside an approved management path.", "Do not match known monitoring, backup, CI/CD, inventory, scanner, or administrative workflows unless rule-specific high-risk evidence remains." },
            FalsePositives = new[] { "Engineering workstations, PLC programming sessions, historian jobs, and approved vendor maintenance can produce these commands; require approved-source tuning." },
            TextIndicators = new[] { "bacnet devicecommunicationcontrol", "bacnet", "device", "communication", "control", "modbus", "s7", "dnp3", "opc", "profinet", "goose", "mms", "write", "function" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "read device identification", "write property", "devicecommunicationcontrol" },
            ProcessIndicators = new[] { "tia", "step7", "plc", "codesys", "modbuspoll", "opcua", "engineering", "hmi", "scada" },
            ProtocolIndicators = new[] { "bacnet" },
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 47808 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 86,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(10),
            Cooldown = TimeSpan.FromMinutes(45),
            DistinctBy = "source+destination+oticsdeep+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedEngineeringWorkstations", "ApprovedVendorJumpHosts", "CriticalAssetRanges", "CommandThreshold" },
            RequiredTests = new[] { "positive R486 evidence-gated sample", "negative R486 descriptor-only sample", "negative R486 missing telemetry sample", "negative R486 approved-admin sample" },
            RequireCrossBoundary = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R486_BACnetDeviceCommunicationControlRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
            => EvaluateSpec(context, Spec);
    }
}
