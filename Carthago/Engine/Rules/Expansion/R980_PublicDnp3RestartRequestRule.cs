// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2697 / AN1933.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R980_PublicDnp3RestartRequestRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R980", Name: "Public DNP3 cold or warm restart request", Category: "IotOtAdvanced",
            Description: "Public IPv4 master sends a capture-validated DNP3 cold/warm restart request to a private outstation on UDP/20000. Authorization, device identity and restart outcome unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R980.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R980", Name = "Public DNP3 cold or warm restart request", Category = "IotOtAdvanced",
            Description = "workbook.R2697 AN1933: exact DNP3 restart request projection; not the workbook's SIPROTEC exploit or evidence of an actual restart.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "dnp3.restart_request.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Complete IPv4 UDP/20000 to UDP/20000, exact 15-byte master unconfirmed user-data frame, valid header/data CRC, distinct nonreserved link addresses, single transport/application request fragment, function 0x0D or 0x0E without objects." },
            NegativeConditions = new[] { "Other function/direction, response, fragmented or object-bearing request, reserved/equal link peers, invalid CRC, incomplete datagram and contradictory evidence fail closed." },
            FalsePositives = new[] { "Authorized remote engineering, recovery and maintenance may issue these requests; approved-source and maintenance context required for promotion." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "public_private_dnp3_restart_request",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "raw cold/warm restart captures with sequence/address boundaries", "independent CRC fixture and known vector",
                "other functions, direction, fragments, addresses, malformed CRC/length", "scope/datagram completeness, forgery and contradictory fields",
                "adjacent DNP3 observation separation, cooldown, duplicates, peer isolation, privacy and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R980_PublicDnp3RestartRequestRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.UdpData(r) || !Research786NetworkEvidence.PublicPrivate(r) ||
                r.SourcePort != 20000 || r.DestinationPort != 20000 || r.L4Len != 15 ||
                !r.Dnp3RestartRequestObserved || r.Dnp3UnsolicitedBinaryEventObserved ||
                r.ApplicationProtocol != "dnp3.restart.request" ||
                r.DnsQname != null || r.DnsIsResponse || r.HttpUri != null || r.HttpMethod != null ||
                r.TlsVersion != null || r.Sni != null) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2697", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "capture_decoded_external_dnp3_cold_or_warm_restart", "rule"),
                new DetectionEvidenceItem("outcome", "request_only_approval_and_restart_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "External DNP3 cold or warm restart request observed; approval, acceptance and restart outcome unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_dnp3_restart_request_crc_checked");
                    confidence.AddEvidence(0.35, "public_to_private_control_boundary");
                }, count: 1, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
