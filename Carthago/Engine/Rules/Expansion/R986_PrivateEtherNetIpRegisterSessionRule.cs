// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2782 / AN2253.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R986_PrivateEtherNetIpRegisterSessionRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R986", Name: "Private EtherNet/IP RegisterSession with public client", Category: "IotOtAdvanced",
            Description: "Private IPv4 TCP/44818 server returns a capture-correlated successful EtherNet/IP RegisterSession response to a public client. Asset role and authorization unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R986.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R986", Name = "Private EtherNet/IP RegisterSession with public client", Category = "IotOtAdvanced",
            Description = "workbook.R2782 AN2253: native EtherNet/IP session registration reachability; not authenticated access or policy violation.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "enip.register_session.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Complete IPv4 TCP/44818 SYN and matching SYN-ACK, exact 28-byte RegisterSession request and response, zero request handle, nonzero response handle, status/options zero, version 1 and matching opaque sender context, <=30 seconds." },
            NegativeConditions = new[] { "Port/label alone, malformed or error frames, wrong session handle, sender context, command or flow, invalid SYN-ACK, missing request, partial/coalesced messages, stale/replayed data and contradictions fail closed." },
            FalsePositives = new[] { "Approved remote operations, engineering and vendor diagnostics can register sessions. Asset role and communication policy are necessary for promotion." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(30),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "private_enip_server_public_client_register_session",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "raw capture sender-context and session-handle boundaries", "malformed/error/context mismatch controls",
                "same flow, valid SYN-ACK, sequence/ACK, reset and expiry", "scope/forgery/contradictions",
                "duplicate/reverse time/cooldown, privacy, isolation and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R986_PrivateEtherNetIpRegisterSessionRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r) ||
                r.SourcePort != 44818 || r.DestinationPort == 44818 || r.L4Len != 28 ||
                !r.EtherNetIpRegisterSessionObserved || r.ApplicationProtocol != "enip.tcp.register_session.response" ||
                r.DnsQname != null || r.DnsIsResponse || r.HttpUri != null || r.HttpMethod != null ||
                r.TlsVersion != null || r.Sni != null) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2782", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "capture_decoded_same_connection_enip_register_session", "rule"),
                new DetectionEvidenceItem("outcome", "session_registration_only_asset_role_authorization_and_operations_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Private EtherNet/IP server completed session registration with a public client; asset role, authorization and subsequent operations unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_enip_register_session_request_and_response");
                    confidence.AddEvidence(0.35, "private_server_public_client_boundary");
                }, count: 1, windowSeconds: 30);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
