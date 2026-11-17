// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R463_ARPGratuitousStormRule.cs
using System;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R463_ARPGratuitousStormRule : LocalDiscoveryWirelessPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R463",
            Name: "ARP Gratuitous Storm",
            Category: "LocalDiscoveryWireless",
            Description: "Capture-origin Ethernet/IPv4 gratuitous ARP announcement burst: 16 source-MAC-consistent broadcasts by one private-IP/MAC pair within 60 seconds. Candidate observation only, not proof of poisoning or compromise.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R463.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R463",
            Name = "ARP Gratuitous Storm",
            Category = "LocalDiscoveryWireless",
            Description = "Detects ARP Gratuitous Storm only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "protocol_or_port" },
            EvidenceFields = new[] { "count", "window_seconds", "matched_conditions", "capture.provenance" },
            PositiveConditions = new[] { "ARP Gratuitous Storm requires observable LocalDiscoveryWireless telemetry and will not match descriptor text alone.", "Source and destination, host, process, protocol, path, port, or payload evidence must be present.", "The configured signal count and time-window threshold must be satisfied before a DetectionEvent is emitted." },
            NegativeConditions = new[] { "Do not match on product names, rule names, documentation text, or generic banners alone.", "Do not match when source/destination context is absent or when the traffic is inside an approved management path.", "Do not match known monitoring, backup, CI/CD, inventory, scanner, or administrative workflows unless rule-specific high-risk evidence remains." },
            FalsePositives = new[] { "Printer discovery, media casting, Wi-Fi controller polling, MDM enrollment, and ordinary DHCP/ARP behavior can be legitimate on managed subnets." },
            TextIndicators = new[] { "arp gratuitous storm", "arp", "gratuitous", "storm", "discover", "query", "enumeration", "offer", "controller", "mdns", "ssdp", "dhcp" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "gratuitous arp", "duplicate mac" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = new[] { "arp" },
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 76,
            WindowThreshold = 16,
            Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+ethernet_sender_mac+packet_id",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedDiscoverySubnets", "ApprovedControllers", "BurstThreshold", "DiscoveryWindowSeconds" },
            RequiredTests = new[] { "positive R463 evidence-gated sample", "negative R463 descriptor-only sample", "negative R463 missing telemetry sample", "negative R463 approved-admin sample" },

        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R463_ARPGratuitousStormRule() : base(Rule, Profile) { }

        // PacketHandler's real Ethernet ARP decoder sets the internal sender-MAC
        // consistency flag. Imported TrafficRecord labels cannot set it.
        // The window/cooldown are instance-owned and bounded, not shared across rules.
        private readonly NetworkBatch226230Evidence.Window _observations = new();
        private readonly WebSignatureCooldown _cooldown = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (r.Id == Guid.Empty || context.TimestampUtc.Kind != DateTimeKind.Utc
                || !r.ArpSenderMacMatchesFrame
                || !string.Equals(r.Protocol, "ARP", StringComparison.Ordinal)
                || !string.Equals(r.ProtocolVersion, "ARP/IPv4", StringComparison.Ordinal)
                || !string.Equals(r.ApplicationProtocol, "ARP", StringComparison.Ordinal)
                || r.IsTcp || r.IsUdp || r.IpVersion.HasValue
                || r.SourcePort.HasValue || r.DestinationPort.HasValue
                || !string.Equals(r.MacDestination, "FF:FF:FF:FF:FF:FF", StringComparison.OrdinalIgnoreCase)
                || string.IsNullOrWhiteSpace(r.MacSource)
                || !string.Equals(r.Source, r.Destination, StringComparison.Ordinal))
                return NoMatch();

            // ARP addresses are not routable Internet evidence. Exclude loopback,
            // multicast, unspecified and link-local initialization chatter.
            if (!IPAddress.TryParse(r.Source, out var source)
                || source.AddressFamily != AddressFamily.InterNetwork
                || !IsRfc1918(source))
                return NoMatch();

            var key = source + "|" + r.MacSource!.ToUpperInvariant();
            var count = _observations.Observe(key, "gratuitous-arp", r.Id,
                context.TimestampUtc, TimeSpan.FromSeconds(60), distinctTargets: false);
            if (count < 16) return NoMatch();

            var cooldown = _cooldown.Observe(source.ToString(), r.MacSource!, r.Id, context.TimestampUtc);
            if (cooldown == WebSignatureObservation.None) return NoMatch();
            if (cooldown == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Sixteen capture-decoded gratuitous ARP broadcasts from one local source/MAC within 60 seconds; failover, host initialization and poisoning outcomes unverified.",
                new[]
                {
                    new DetectionEvidenceItem("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                    new DetectionEvidenceItem("window_seconds", "60", "rule"),
                    new DetectionEvidenceItem("capture.provenance", "ethernet_arp_sender_mac_consistent", "packet-handler"),
                    new DetectionEvidenceItem("matched_conditions", "gratuitous_arp_broadcast,private_source,unique_packet_ids,60s_burst", "rule")
                },
                confidence =>
                {
                    confidence.AddEvidence(0.40, "capture-decoded-arp-ethernet-consistency");
                    confidence.AddEvidence(0.28, "identical-sender-target-ip-and-broadcast");
                    confidence.AddCorrelation(0.16, "sixteen-distinct-frames-within-60s");
                }, count: count, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        private static bool IsRfc1918(IPAddress ip)
        {
            var bytes = ip.GetAddressBytes();
            return bytes[0] == 10 || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
                || (bytes[0] == 192 && bytes[1] == 168);
        }
    }
}
