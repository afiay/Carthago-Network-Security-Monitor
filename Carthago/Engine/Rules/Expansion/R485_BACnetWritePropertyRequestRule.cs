// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R485_BACnetWritePropertyRequestRule.cs
using System;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R485_BACnetWritePropertyRequestRule : OtIcsDeepPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R485",
            Name: "BACnet WriteProperty Request",
            Category: "OtIcsDeep",
            Description: "Shadow-only candidate for a validated BACnet/IP unsegmented confirmed WriteProperty request crossing a trust boundary; no device modification claimed.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R485.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R485",
            Name = "BACnet WriteProperty Request",
            Category = "OtIcsDeep",
            Description = "Captured BACnet/IP confirmed WriteProperty request, not a successful write outcome.",
            Severity = SeverityLevel.Critical,
            Maturity = RulePrecisionMaturity.Candidate,
            RequiredTelemetry = new[] { RuleTelemetryKind.Packet, RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            RequiredFields = new[] { "source", "destination", "capture_only_bacnet_writeproperty" },
            EvidenceFields = new[] { "network.destinationPort", "ot.protocol", "function.code", "matched_conditions" },
            PositiveConditions = new[] { "Require complete BACnet/IP unicast BVLC, NPDU and unsegmented ConfirmedRequest WriteProperty service 15, with syntactically present object/property target.", "Require capture-proven direction and a trust boundary; do not infer device acceptance or write outcome." },
            NegativeConditions = new[] { "Do not match on product names, rule names, documentation text, or generic banners alone.", "Do not match when source/destination context is absent or when the traffic is inside an approved management path.", "Do not match known monitoring, backup, CI/CD, inventory, scanner, or administrative workflows unless rule-specific high-risk evidence remains." },
            FalsePositives = new[] { "Engineering workstations, PLC programming sessions, historian jobs, and approved vendor maintenance can produce these commands; require approved-source tuning." },
            TextIndicators = new[] { "bacnet writeproperty request", "bacnet", "write", "property", "request", "modbus", "s7", "dnp3", "opc", "profinet", "goose", "mms", "control", "function" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "read device identification", "write property", "devicecommunicationcontrol" },
            ProcessIndicators = new[] { "tia", "step7", "plc", "codesys", "modbuspoll", "opcua", "engineering", "hmi", "scada" },
            ProtocolIndicators = new[] { "bacnet" },
            Methods = new[] { "post", "put", "connect" },
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
            RequiredTests = new[] { "positive R485 raw UDP confirmed WriteProperty Shadow sample", "negative R485 ReadProperty and WritePropertyMultiple", "negative R485 segmented, broadcast, truncated and wrong direction", "negative R485 descriptor-only, private-only boundary, policy and privacy" },
            RequireCrossBoundary = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R485_BACnetWritePropertyRequestRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (string.IsNullOrWhiteSpace(record.Destination))
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                    "BACNET_WRITE_PROPERTY_NOT_OBSERVED",
                    "A destination and decoded BACnet WriteProperty request must be observed.");

            if (string.IsNullOrWhiteSpace(record.Source))
                return NoMatch(RuleNoMatchReasonCategory.MissingTelemetry,
                    "MISSING_CORE_TELEMETRY", "A captured source is required before R485 evaluation.");

            if (!record.BacnetWritePropertyRequestObserved
                || !record.IsUdp || record.IsTcp || record.IsQuic
                || record.DestinationPort != 47808
                || !string.Equals(record.ApplicationProtocol, "bacnet.writeproperty.request", StringComparison.Ordinal)
                || record.HttpMethod != null || record.HttpUri != null || record.HttpRequestHeaders != null)
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                    "BACNET_WRITEPROPERTY_CONFIRMED_REQUEST_UNAVAILABLE",
                    "Untrusted BACnet names, port, Info or imported records cannot prove a complete confirmed WriteProperty APDU.");

            if (!IsCrossBoundary(record, out _, out _))
                return NoMatch(RuleNoMatchReasonCategory.BoundaryMismatch,
                    "BACNET_WRITEPROPERTY_EXTERNAL_BOUNDARY_REQUIRED",
                    "R485 requires an observed internal/external boundary.");

            var result = MatchCloudDev(context, SeverityLevel.Critical,
                "BACnet confirmed WriteProperty request crossing trust boundary (write outcome unknown)",
                "OtIcsDeep",
                new[]
                {
                    new DetectionEvidenceItem("ot.protocol", "bacnet.ip", "packet-handler"),
                    new DetectionEvidenceItem("function.code", "confirmed-writeproperty-15", "packet-handler"),
                    new DetectionEvidenceItem("matched_conditions", "complete_unsegmented_apdu,object_property_target,cross_boundary", "rule")
                }, confidence =>
                {
                    confidence.AddEvidence(0.48, "bounded-bacnet-confirmed-request");
                    confidence.AddEvidence(0.26, "decoded-object-and-property-target");
                    confidence.AddCorrelation(0.16, "internal-external-boundary");
                }, count: 1, window: Spec.Window,
                cooldownKey: $"{record.Source}:{record.Destination}:bacnet-writeproperty");
            if (result.Events.Count > 0
                && result.Events[0].SuppressionStatus == DetectionSuppressionStatus.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            foreach (var evt in result.Events)
                ShadowForWeakEvidence(evt, "R485 capture-only candidate; no authenticated BACnet controller, maintenance approval or verified write outcome.");
            return result;
        }
    }
}
