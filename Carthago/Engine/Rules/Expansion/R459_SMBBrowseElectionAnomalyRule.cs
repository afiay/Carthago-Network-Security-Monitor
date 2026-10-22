// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R459_SMBBrowseElectionAnomalyRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R459_SMBBrowseElectionAnomalyRule : LocalDiscoveryWirelessPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R459",
            Name: "SMB Browse Election Anomaly",
            Category: "LocalDiscoveryWireless",
            Description: "Detects SMB Browse Election Anomaly only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R459.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R459",
            Name = "SMB Browse Election Anomaly",
            Category = "LocalDiscoveryWireless",
            Description = "Detects SMB Browse Election Anomaly only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Low,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Dns, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "local_discovery_destination", "protocol_or_service_marker" },
            EvidenceFields = new[] { "network.destinationPort", "local.protocol", "service.name", "matched_conditions" },
            PositiveConditions = new[] { "SMB Browse Election Anomaly requires observable LocalDiscoveryWireless telemetry and will not match descriptor text alone.", "Source and destination, host, process, protocol, path, port, or payload evidence must be present.", "The configured signal count and time-window threshold must be satisfied before a DetectionEvent is emitted." },
            NegativeConditions = new[] { "Do not match on product names, rule names, documentation text, or generic banners alone.", "Do not match when source/destination context is absent or when the traffic is inside an approved management path.", "Do not match known monitoring, backup, CI/CD, inventory, scanner, or administrative workflows unless rule-specific high-risk evidence remains." },
            FalsePositives = new[] { "Printer discovery, media casting, Wi-Fi controller polling, MDM enrollment, and ordinary DHCP/ARP behavior can be legitimate on managed subnets." },
            TextIndicators = new[] { "smb browse election anomaly", "smb", "browse", "election", "anomaly", "discover", "query", "enumeration", "offer", "gratuitous", "controller", "mdns", "ssdp", "arp", "dhcp" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = new[] { "smb" },
            Methods = new[] { "get", "post" },
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 137, 138, 139, 445 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 76,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(5),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+localdiscoverywireless+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedDiscoverySubnets", "ApprovedControllers", "BurstThreshold", "DiscoveryWindowSeconds" },
            RequiredTests = new[] { "positive R459 evidence-gated sample", "negative R459 descriptor-only sample", "negative R459 missing telemetry sample", "negative R459 approved-admin sample" },

        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R459_SMBBrowseElectionAnomalyRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
            => EvaluateSpec(context, Spec);
    }
}
