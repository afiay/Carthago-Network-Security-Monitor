// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R460_NetBIOSNameQuerySweepRule.cs
using System;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R460_NetBIOSNameQuerySweepRule : LocalDiscoveryWirelessPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R460",
            Name: "NetBIOS Name Query Sweep",
            Category: "LocalDiscoveryWireless",
            Description: "Eight distinct complete, capture-decoded NetBIOS NBNS name questions from one private IPv4 source within 60 seconds. Candidate discovery-sweep observation only, not an unauthorized-access finding.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R460.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R460",
            Name = "NetBIOS Name Query Sweep",
            Category = "LocalDiscoveryWireless",
            Description = "Detects NetBIOS Name Query Sweep only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "protocol_or_port" },
            EvidenceFields = new[] { "count", "window_seconds", "matched_conditions", "capture.provenance" },
            PositiveConditions = new[] { "Only complete binary IPv4 UDP/137 first-level NBNS name questions classified by the capture-owned decoder qualify.", "Eight distinct question identities from the same RFC1918 source must occur in 60 seconds.", "Candidates remain in Shadow; activity does not prove unauthorized access." },
            NegativeConditions = new[] { "Do not match generic UDP/137, spoofable Info text, imported records, DNS qnames, server responses or malformed/partial name questions.", "Deduplicate packet IDs and name identities, reject expired/out-of-order windows and preserve host isolation.", "Normal WINS/NetBIOS administrative inventory may be benign; never infer compromise." },
            FalsePositives = new[] { "Printer discovery, media casting, Wi-Fi controller polling, MDM enrollment, and ordinary DHCP/ARP behavior can be legitimate on managed subnets." },
            TextIndicators = new[] { "netbios name query sweep", "net", "bios", "name", "query", "sweep", "discover", "enumeration", "offer", "gratuitous", "controller", "mdns", "ssdp", "arp", "dhcp" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = new[] { "get", "post" },
            TokenKinds = Array.Empty<string>(),
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 76,
            WindowThreshold = 8,
            Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+distinct_decoded_nbns_name_questions",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedDiscoverySubnets", "ApprovedControllers", "BurstThreshold", "DiscoveryWindowSeconds" },
            RequiredTests = new[] { "positive R460 evidence-gated sample", "negative R460 descriptor-only sample", "negative R460 missing telemetry sample", "negative R460 approved-admin sample" },

        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R460_NetBIOSNameQuerySweepRule() : base(Rule, Profile) { }

        private readonly NetworkBatch226230Evidence.Window _questions = new();
        private readonly WebSignatureCooldown _cooldown = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (r.Id == Guid.Empty || context.TimestampUtc.Kind != DateTimeKind.Utc
                || string.IsNullOrWhiteSpace(r.NbnsQueryNameDigest)
                || !r.IsUdp || r.IsTcp || r.IpVersion != 4
                || !string.Equals(r.Protocol, "UDP", StringComparison.Ordinal)
                || r.DestinationPort != 137 || r.L4Len != 50
                || r.SourcePort is not int sourcePort || sourcePort is < 1 or > 65535
                || !IPAddress.TryParse(r.Source, out var sourceIp)
                || sourceIp.AddressFamily != AddressFamily.InterNetwork
                || !IPAddress.TryParse(r.Destination, out _))
                return NoMatch();

            var b = sourceIp.GetAddressBytes();
            if (!(b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31)
                || (b[0] == 192 && b[1] == 168)))
                return NoMatch();

            // The digest is set exclusively by the complete UDP datagram decoder.
            // Importable packet fields or name labels never enter this bounded window.
            int distinctNames = _questions.Observe(sourceIp.ToString(), r.NbnsQueryNameDigest,
                r.Id, context.TimestampUtc, TimeSpan.FromSeconds(60), distinctTargets: true);
            if (distinctNames < 8) return NoMatch();

            var state = _cooldown.Observe(sourceIp.ToString(), "nbns-distinct-names",
                r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Eight distinct capture-decoded NetBIOS name questions from one local source in 60 seconds; administrative discovery and security outcome unverified.",
                new[]
                {
                    new DetectionEvidenceItem("count", distinctNames.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                    new DetectionEvidenceItem("window_seconds", "60", "rule"),
                    new DetectionEvidenceItem("capture.provenance", "complete_ipv4_udp_nbns_question", "packet-handler"),
                    new DetectionEvidenceItem("matched_conditions", "eight_distinct_encoded_netbios_names,per_source,60s_window", "rule")
                },
                confidence =>
                {
                    confidence.AddEvidence(0.40, "capture-decoded-netbios-question");
                    confidence.AddEvidence(0.26, "eight-distinct-private-source-names");
                    confidence.AddCorrelation(0.18, "monotonic-60-second-window");
                }, count: distinctNames, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
