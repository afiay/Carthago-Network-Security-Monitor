// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R486_BACnetDeviceCommunicationControlRule.cs
using System;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R486_BACnetDeviceCommunicationControlRule : OtIcsDeepPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R486",
            Name: "BACnet DeviceCommunicationControl",
            Category: "OtIcsDeep",
            Description: "Shadow-only candidate for a captured unsegmented BACnet/IP DeviceCommunicationControl disable request crossing a trust boundary; controller outcome unknown.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R486.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R486",
            Name = "BACnet DeviceCommunicationControl",
            Category = "OtIcsDeep",
            Description = "Validated BACnet/IP Disable or DisableInitiation DeviceCommunicationControl request, not verified device disruption.",
            Severity = SeverityLevel.Critical,
            Maturity = RulePrecisionMaturity.Candidate,
            RequiredTelemetry = new[] { RuleTelemetryKind.Packet, RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            RequiredFields = new[] { "source", "destination", "capture_only_bacnet_dcc_disable" },
            EvidenceFields = new[] { "network.destinationPort", "ot.protocol", "function.code", "matched_conditions" },
            PositiveConditions = new[] { "Require a complete captured unsegmented BACnet/IPv4 ConfirmedRequest DeviceCommunicationControl service 17 with disable enum 1 or 2 and an Original-Unicast BVLC function; transport unicast and controller identity are not independently proven.", "Require an internal/external trust boundary and capture provenance; never assert that the device accepted the command or ceased communication." },
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
            RequiredTests = new[] { "positive R486 captured DCC disable and disable-initiation Shadow", "negative R486 enable, read, broadcast, segmented, malformed and password-bearing", "negative R486 imported text/JSON, missing boundary, truncated IP and wrong direction", "negative R486 privacy, cooldown and profile invariants" },
            RequireCrossBoundary = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R486_BACnetDeviceCommunicationControlRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (string.IsNullOrWhiteSpace(record.Source) || string.IsNullOrWhiteSpace(record.Destination))
                return NoMatch(RuleNoMatchReasonCategory.MissingTelemetry,
                    "MISSING_CORE_TELEMETRY", "R486 requires a captured source and destination.");

            if (!record.BacnetDeviceCommunicationDisableObserved
                || !record.IsUdp || record.IsTcp || record.IsQuic
                || record.DestinationPort != 47808
                || !string.Equals(record.ApplicationProtocol,
                    "bacnet.devicecommunicationcontrol.disable", StringComparison.Ordinal)
                || record.HttpMethod != null || record.HttpUri != null || record.HttpRequestHeaders != null)
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                    "BACNET_DEVICE_COMMUNICATION_CONTROL_REQUEST_UNAVAILABLE",
                    "Only a complete, capture-backed unsegmented DCC disable request qualifies; port, protocol names and imported text do not.");

            if (!IsCrossBoundary(record, out _, out _))
                return NoMatch(RuleNoMatchReasonCategory.BoundaryMismatch,
                    "BACNET_DCC_EXTERNAL_BOUNDARY_REQUIRED",
                    "The captured request must cross an internal/external trust boundary.");

            var result = MatchCloudDev(context, SeverityLevel.Critical,
                "BACnet DeviceCommunicationControl disable request across trust boundary (outcome unknown)",
                "OtIcsDeep",
                new[]
                {
                    new DetectionEvidenceItem("ot.protocol", "bacnet.ip", "packet-handler"),
                    new DetectionEvidenceItem("function.code", "confirmed-devicecommunicationcontrol-17", "packet-handler"),
                    new DetectionEvidenceItem("matched_conditions", "complete_unsegmented_disable_request,bvlc_original_unicast_function,cross_boundary", "rule")
                }, confidence =>
                {
                    confidence.AddEvidence(0.46, "bounded-bacnet-confirmed-dcc-request");
                    confidence.AddEvidence(0.25, "decoded-disable-enumeration");
                    confidence.AddCorrelation(0.18, "internal-external-boundary");
                }, count: 1, window: Spec.Window,
                cooldownKey: $"{record.Source}:{record.Destination}:bacnet-dcc-disable");

            if (result.Events.Count > 0
                && result.Events[0].SuppressionStatus == DetectionSuppressionStatus.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            foreach (var evt in result.Events)
                ShadowForWeakEvidence(evt, "R486 capture-only DCC candidate; no authenticated controller, approved operation or verified communication interruption.");
            return result;
        }
    }
}
