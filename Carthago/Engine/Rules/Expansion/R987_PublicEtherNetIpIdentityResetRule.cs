// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2697 / AN1933.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R987_PublicEtherNetIpIdentityResetRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R987", Name: "Public EtherNet/IP CIP Identity Reset request", Category: "IotOtAdvanced",
            Description: "Public IPv4 client issues an exact unconnected CIP Identity Object type-zero Reset after capture-qualified EtherNet/IP RegisterSession to private TCP/44818. Authorization, acceptance and restart unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R987.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R987", Name = "Public EtherNet/IP CIP Identity Reset request", Category = "IotOtAdvanced",
            Description = "workbook.R2697 AN1933: narrow restart request projection, not evidence of device downtime or the SIPROTEC exploit.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "destination.port", "packet.id", "enip.identity_reset.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Verified TCP handshake and RegisterSession exchange; next complete client SendRRData payload with matching handle, exact CPF null address and unconnected data, CIP Reset 05 path class 1 instance 1 type 0 within 30 seconds." },
            NegativeConditions = new[] { "Registration alone, other CIP services or reset types, wrong session/path/CPF, error, incomplete/coalesced or replayed data, missing/cross-flow registration, invalid TCP or wrong scope fail closed." },
            FalsePositives = new[] { "Authorized engineering, commissioning and recovery may request restart. Asset-specific approval, change-control and device-state corroboration required for promotion." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(30),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "public_private_enip_identity_reset",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "raw complete session and Reset capture", "ordinary CIP and malformed CPF/handle/path controls",
                "wrong handshake/session, expiry, reset and replay", "scope, forgery and contradictory evidence",
                "duplicate/reverse time/cooldown, peer isolation, privacy and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R987_PublicEtherNetIpIdentityResetRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PublicPrivate(r) ||
                r.DestinationPort != 44818 || r.SourcePort == 44818 || r.L4Len != 47 ||
                !r.EtherNetIpIdentityResetObserved || r.EtherNetIpRegisterSessionObserved ||
                r.ApplicationProtocol != "enip.tcp.identity_reset.request" ||
                r.DnsQname != null || r.DnsIsResponse || r.HttpUri != null || r.HttpMethod != null ||
                r.TlsVersion != null || r.Sni != null) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2697", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "capture_decoded_registered_enip_cip_identity_reset_type_zero", "rule"),
                new DetectionEvidenceItem("outcome", "request_only_approval_acceptance_and_restart_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "External EtherNet/IP CIP Identity Reset request observed after successful session registration; approval, acceptance and restart unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_cip_identity_reset_on_verified_session");
                    confidence.AddEvidence(0.35, "public_to_private_control_boundary");
                }, count: 1, windowSeconds: 30);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
