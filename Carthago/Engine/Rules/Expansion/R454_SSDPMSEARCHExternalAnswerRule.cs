// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R454_SSDPMSEARCHExternalAnswerRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R454_SSDPMSEARCHExternalAnswerRule : LocalDiscoveryWirelessPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R454",
            Name: "SSDP MSEARCH External Answer",
            Category: "LocalDiscoveryWireless",
            Description: "Detects SSDP MSEARCH External Answer only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R454.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R454",
            Name = "SSDP MSEARCH External Answer",
            Category = "LocalDiscoveryWireless",
            Description = "Detects SSDP MSEARCH External Answer only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Medium,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Dns, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "local_discovery_destination", "protocol_or_service_marker" },
            EvidenceFields = new[] { "network.destinationPort", "local.protocol", "service.name", "matched_conditions" },
            PositiveConditions = new[] { "SSDP MSEARCH External Answer requires observable LocalDiscoveryWireless telemetry and will not match descriptor text alone.", "Source and destination, host, process, protocol, path, port, or payload evidence must be present.", "The configured signal count and time-window threshold must be satisfied before a DetectionEvent is emitted." },
            NegativeConditions = new[] { "Do not match on product names, rule names, documentation text, or generic banners alone.", "Do not match when source/destination context is absent or when the traffic is inside an approved management path.", "Do not match known monitoring, backup, CI/CD, inventory, scanner, or administrative workflows unless rule-specific high-risk evidence remains." },
            FalsePositives = new[] { "Printer discovery, media casting, Wi-Fi controller polling, MDM enrollment, and ordinary DHCP/ARP behavior can be legitimate on managed subnets." },
            TextIndicators = new[] { "ssdp msearch external answer", "ssdp", "search", "answer", "discover", "query", "enumeration", "offer", "gratuitous", "controller", "mdns", "arp", "dhcp" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "m-search", "ssdp:discover", "upnp:rootdevice" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = new[] { "ssdp" },
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 1900 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 76,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(5),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+localdiscoverywireless+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedDiscoverySubnets", "ApprovedControllers", "BurstThreshold", "DiscoveryWindowSeconds" },
            RequiredTests = new[] { "positive R454 evidence-gated sample", "negative R454 descriptor-only sample", "negative R454 missing telemetry sample", "negative R454 approved-admin sample" },

        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R454_SSDPMSEARCHExternalAnswerRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
            => EvaluateSpec(context, Spec);
    }
}
