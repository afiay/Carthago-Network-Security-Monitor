// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>SMB2 WRITE requests from one private host to three public /24 networks.</summary>
    public sealed class R584_OutboundSmb2WriteSubnetFanoutRule
        : ExfiltrationAdvancedPrecisionDetectionRuleBase
    {
        private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R584", Name: "Outbound SMB2 WRITE Request Public Subnet Fanout",
            Category: "ExfiltrationAdvanced",
            Description: "A private client sends bounded SMB2 WRITE request shapes to three distinct public /24 networks on TCP/445 in five minutes; neither writes nor transfers are confirmed.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R584.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateExfiltrationProfile(
            ruleId: "R584", maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Payload },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_port" },
            evidenceFields: new[] { "smb.operation", "matched_conditions", "count", "window_seconds", "smb.outcome" },
            positiveConditions: new[]
            {
                "PacketHandler/NetworkBatch246250Wire classifies a bounded first-segment SMB2 WRITE request, not a response.",
                "One RFC1918 source contacts three distinct public destination /24 networks via TCP/445 in five minutes.",
                "Require coherent IPv4/TCP, independent packet IDs, monotonic times and bounded correlation memory."
            },
            negativeConditions: new[]
            {
                "Reject SMB2 CREATE, responses, generic port/Info-only signals, private/reserved endpoints and one /24.",
                "Reject TLS, QUIC, contradictory HTTP/DNS/Redis fields, truncated records, duplicates and stale observations.",
                "Do not infer successfully written files, data contents, mounted shares, external service identity or exfiltration."
            },
            minimumConfidence: 88, threshold: 3, window: Window, cooldown: Cooldown,
            distinctBy: "private_smb_client+distinct_public_destination_24",
            falsePositives: new[]
            {
                "Approved external SMB file services and distributed deployment or backup tools may send writes.",
                "SMB encryption and segmented payloads can hide request shape; NAT and proxies may affect attribution."
            },
            tuningKnobs: new[] { "Mode", "ApprovedFileTransferHosts", "ApprovedMaintenanceWindows" },
            requiredTests: new[]
            {
                "SMB2 WRITE wire producer and CREATE/response negatives", "three public /24s",
                "reserved endpoint, contradictory and truncated metadata negatives",
                "source isolation, duplicate, order, expiry and cooldown",
                "privacy, Candidate Shadow and unique registry ID"
            });
        private readonly CrossBoundaryRequestFanoutWindow _window = new();

        public R584_OutboundSmb2WriteSubnetFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!CrossBoundaryRequestEvidence.Tcp(r, 117, 4096)
                || r.DestinationPort != 445
                || !string.Equals(r.ApplicationProtocol, "smb2.write.request", StringComparison.Ordinal)
                || !CrossBoundaryRequestEvidence.NoHttpOrConflictingParserFlags(r)
                || !CrossBoundaryRequestEvidence.NoRedisParserFlags(r)
                || !CrossBoundaryRequestEvidence.TryPair(r, publicToPrivate: false,
                    out var client, out var target24))
                return NoMatch();
            var observation = _window.Observe(client, target24, r.Id, context.TimestampUtc);
            if (observation == FanoutObservation.None) return NoMatch();
            if (observation == FanoutObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("smb.operation", "smb2.write.request", "bounded-packet-classifier"),
                new DetectionEvidenceItem("matched_conditions", "private_to_public,three_distinct_public_24s", "rule"),
                new DetectionEvidenceItem("count", "3", "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule"),
                new DetectionEvidenceItem("smb.outcome", "request_only_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "Outbound SMB2 WRITE request fanout (file transfer outcome unverified)",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "bounded-smb2-write-request-shape");
                    confidence.AddEvidence(0.24, "private-to-public-smb");
                    confidence.AddCorrelation(0.20, "three-distinct-public-24s");
                }, count: 3, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
