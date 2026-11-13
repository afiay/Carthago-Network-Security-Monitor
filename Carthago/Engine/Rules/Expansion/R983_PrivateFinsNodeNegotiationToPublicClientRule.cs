// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2782 / AN2253.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R983_PrivateFinsNodeNegotiationToPublicClientRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R983", Name: "Private FINS/TCP node negotiation with public client", Category: "IotOtAdvanced",
            Description: "Private IPv4 TCP/9600 server returns a capture-correlated successful FINS/TCP node-address response to a public client. Asset role and authorization unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R983.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R983", Name = "Private FINS/TCP node negotiation with public client", Category = "IotOtAdvanced",
            Description = "workbook.R2782 AN2253: native FINS/TCP node negotiation reachability; not authenticated access or policy violation.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "fins.node_negotiation.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Complete IPv4 TCP/9600 SYN and matching SYN-ACK, exact first FINS command 0 request and command 1 successful response, valid distinct nodes, matching requested node or automatic assignment, <=30 seconds." },
            NegativeConditions = new[] { "Port/label alone, malformed or error frames, wrong node, command or flow, invalid SYN-ACK, missing request, partial/coalesced messages, stale/replayed data and contradictions fail closed." },
            FalsePositives = new[] { "Approved remote operations, engineering and vendor diagnostics can negotiate nodes. Asset role and communication policy are necessary for promotion." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(30),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "private_fins_server_public_client_node_negotiation",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "raw capture automatic and explicit node boundaries", "malformed/error/node mismatch controls",
                "same flow, valid SYN-ACK, sequence/ACK, reset and expiry", "scope/forgery/contradictions",
                "duplicate/reverse time/cooldown, privacy, isolation and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R983_PrivateFinsNodeNegotiationToPublicClientRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r) ||
                r.SourcePort != 9600 || r.DestinationPort == 9600 || r.L4Len != 24 ||
                !r.FinsNodeNegotiationObserved || r.ApplicationProtocol != "fins.tcp.node_negotiation.response" ||
                r.DnsQname != null || r.DnsIsResponse || r.HttpUri != null || r.HttpMethod != null ||
                r.TlsVersion != null || r.Sni != null) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2782", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "capture_decoded_same_connection_fins_node_negotiation", "rule"),
                new DetectionEvidenceItem("outcome", "node_negotiation_only_asset_role_authorization_and_operations_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Private FINS/TCP server completed node-address negotiation with a public client; asset role, authorization and subsequent operations unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_fins_node_request_and_response");
                    confidence.AddEvidence(0.35, "private_server_public_client_boundary");
                }, count: 1, windowSeconds: 30);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
