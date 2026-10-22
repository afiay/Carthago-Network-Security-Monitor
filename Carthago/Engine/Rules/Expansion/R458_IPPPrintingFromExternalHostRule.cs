// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R458_IPPPrintingFromExternalHostRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R458_IPPPrintingFromExternalHostRule : LocalDiscoveryWirelessPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R458",
            Name: "IPP Printing From External Host",
            Category: "LocalDiscoveryWireless",
            Description: "Detects IPP Printing From External Host only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R458.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R458",
            Name = "IPP Printing From External Host",
            Category = "LocalDiscoveryWireless",
            Description = "Detects IPP Printing From External Host only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Medium,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Dns, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "local_discovery_destination", "protocol_or_service_marker" },
            EvidenceFields = new[] { "network.destinationPort", "local.protocol", "service.name", "matched_conditions" },
            PositiveConditions = new[] { "IPP Printing From External Host requires observable LocalDiscoveryWireless telemetry and will not match descriptor text alone.", "Source and destination, host, process, protocol, path, port, or payload evidence must be present.", "The configured signal count and time-window threshold must be satisfied before a DetectionEvent is emitted." },
            NegativeConditions = new[] { "Do not match on product names, rule names, documentation text, or generic banners alone.", "Do not match when source/destination context is absent or when the traffic is inside an approved management path.", "Do not match known monitoring, backup, CI/CD, inventory, scanner, or administrative workflows unless rule-specific high-risk evidence remains." },
            FalsePositives = new[] { "Printer discovery, media casting, Wi-Fi controller polling, MDM enrollment, and ordinary DHCP/ARP behavior can be legitimate on managed subnets." },
            TextIndicators = new[] { "ipp printing from external host", "ipp", "printing", "host", "discover", "query", "enumeration", "offer", "gratuitous", "controller", "mdns", "ssdp", "arp", "dhcp" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 631 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 76,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(5),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+localdiscoverywireless+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedDiscoverySubnets", "ApprovedControllers", "BurstThreshold", "DiscoveryWindowSeconds" },
            RequiredTests = new[] { "positive R458 evidence-gated sample", "negative R458 descriptor-only sample", "negative R458 missing telemetry sample", "negative R458 approved-admin sample" },

        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R458_IPPPrintingFromExternalHostRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
            => EvaluateSpec(context, Spec);
    }
}
