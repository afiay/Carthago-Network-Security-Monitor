// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2782 / AN2253.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R973_PrivateOpcUaHelloAckToPublicClientRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R973", Name: "Private OPC UA server HEL/ACK exchange with public client", Category: "IotOtAdvanced",
            Description: "Private IPv4 TCP/4840 server sends an exact OPC UA ACK after a complete same-connection public client HEL. Asset role, approval, authentication and API execution unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R973.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R973", Name = "Private OPC UA server HEL/ACK exchange with public client", Category = "IotOtAdvanced",
            Description = "workbook.R2782 AN2253: capture-qualified application transport reachability, not authenticated access or confirmed OT asset inventory.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "opcua.hello_ack.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Complete IPv4 TCP SYN/SYN-ACK and exact first HEL and ACK, same flow, sequence/ACK contiguous, compatible version and buffer sizes, <=30 seconds, private server to public client." },
            NegativeConditions = new[] { "TCP handshake alone, ERR/OPN, malformed/partial/coalesced messages, incorrect buffers, missing/cross-flow HEL, gap/retransmit, expiry or wrong scope fail closed." },
            FalsePositives = new[] { "Authorized remote OPC UA monitoring, diagnostics and legitimate externally routed service clients can complete this exchange." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(30),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "private_opcua_server_public_client_hello_ack",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "raw HEL/ACK capture positive and TCP-only negative", "HEL/ACK format and buffer boundaries",
                "same flow, TCP ACK/sequence, expiry and reset", "scope/forgery/contradictions", "cooldown, isolation, privacy and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R973_PrivateOpcUaHelloAckToPublicClientRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r) ||
                r.SourcePort != 4840 || r.DestinationPort == 4840 || r.L4Len != 28 ||
                !r.OpcUaHelloAckObserved || r.DnsQname != null || r.DnsIsResponse ||
                r.HttpUri != null || r.HttpMethod != null || r.TlsVersion != null || r.Sni != null) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2782", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "capture_decoded_same_connection_opcua_hello_ack", "rule"),
                new DetectionEvidenceItem("outcome", "transport_ack_only_authentication_api_and_asset_role_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Private OPC UA server acknowledged a public client HEL; authorization, authentication and API execution unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_opcua_hello_ack_structure");
                    confidence.AddEvidence(0.35, "private_server_public_client_boundary");
                }, count: 1, windowSeconds: 30);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
