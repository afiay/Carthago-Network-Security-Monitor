// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>Private BACnet host discovers three public target networks.</summary>
    public sealed class R583_OutboundBacnetWhoIsSubnetFanoutRule
        : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R583", Name: "Outbound BACnet Who-Is Public Subnet Fanout",
            Category: "IotOtAdvanced",
            Description: "One private BACnet source sends classified Who-Is requests to three different public /24 networks in five minutes; device replies are unknown.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R583.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R583", maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port" },
            evidenceFields: new[] { "bacnet.operation", "matched_conditions", "count", "window_seconds", "bacnet.outcome" },
            positiveConditions: new[]
            {
                "Existing bounded UDP classifier identifies BACnet/IP Who-Is on UDP/47808 in client-to-target direction.",
                "One RFC1918 IPv4 source queries three distinct globally routable public IPv4 /24 networks in five minutes.",
                "Require valid typed UDP/IPv4 metadata, unique packet identifiers and monotonic bounded state."
            },
            negativeConditions: new[]
            {
                "Reject I-Am, other BACnet operations, generic UDP/47808, multicast, private or reserved targets.",
                "Reject repeated same /24, malformed/truncated, Info-only, conflicting HTTP/DNS/TLS or reverse direction.",
                "Do not infer BACnet device existence, server responses, authenticated sender or malicious exploitation."
            },
            minimumConfidence: 82, threshold: 3, window: Window, cooldown: Cooldown,
            distinctBy: "private_bacnet_source+distinct_public_destination_24",
            falsePositives: new[]
            {
                "Authorized foreign-device registration, building-management gateways and security inventories may cross the internet.",
                "UDP source spoofing, BBMD routing and capture vantage point limit attribution."
            },
            tuningKnobs: new[] { "Mode", "ApprovedBacnetGateways", "ApprovedCommissioningWindows" },
            requiredTests: new[]
            {
                "real bounded BACnet Who-Is wire classification", "I-Am and port-only negatives",
                "three distinct /24s versus repeated subnet and multicast",
                "duplicate, ordering, expiry, cooldown and malformed metadata",
                "redacted aggregate evidence, Candidate Shadow and registry uniqueness"
            });
        private readonly CrossBoundaryRequestFanoutWindow _window = new();

        public R583_OutboundBacnetWhoIsSubnetFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!CrossBoundaryRequestEvidence.Udp(r, 8, 1476)
                || r.SourcePort != 47808 || r.DestinationPort != 47808
                || !CrossBoundaryRequestEvidence.NoRedisParserFlags(r)
                || !NetworkBatch241245Evidence.Bacnet(r, out var op)
                || !string.Equals(op, "whois", StringComparison.Ordinal)
                || !CrossBoundaryRequestEvidence.TryPair(r, publicToPrivate: false,
                    out var client, out var target24))
                return NoMatch();
            var observation = _window.Observe(client, target24, r.Id, context.TimestampUtc);
            if (observation == FanoutObservation.None) return NoMatch();
            if (observation == FanoutObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("bacnet.operation", "whois", "bounded-packet-parser"),
                new DetectionEvidenceItem("matched_conditions", "private_to_public,three_distinct_public_24s", "rule"),
                new DetectionEvidenceItem("count", "3", "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule"),
                new DetectionEvidenceItem("bacnet.outcome", "request_only_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "Outbound BACnet Who-Is discovery across public networks (replies unknown)",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.42, "classified-bacnet-whois");
                    confidence.AddEvidence(0.24, "private-to-public-boundary");
                    confidence.AddCorrelation(0.18, "three-distinct-public-24s");
                }, count: 3, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
