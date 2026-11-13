// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2717 / AN2216.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R981_PublicDnp3DisableUnsolicitedRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R981", Name: "Public DNP3 all-event-class Disable Unsolicited request", Category: "IotOtAdvanced",
            Description: "Public IPv4 master sends an exact DNP3 Disable Unsolicited request for event classes 1, 2 and 3 to private UDP/20000. Approval, acceptance and reporting loss unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R981.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R981", Name = "Public DNP3 all-event-class Disable Unsolicited request", Category = "IotOtAdvanced",
            Description = "workbook.R2717 AN2216: narrow request-side projection, not proof of ceased reporting, continued polling or unauthorized action.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "dnp3.disable_unsolicited.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Complete IPv4 UDP/20000-to-20000 master unconfirmed user data, valid CRCs, distinct nonreserved link peers, one complete fragment, function 0x15 and exactly one each group 60 variations 2, 3, 4 qualifier 06." },
            NegativeConditions = new[] { "Enable Unsolicited, partial/duplicate/extra class selector, other function, direction, qualifier, fragmentation, malformed CRC/length, wrong scope and contradictory evidence fail closed." },
            FalsePositives = new[] { "Authorized startup, commissioning or polling-mode configuration can disable unsolicited reporting. Source approval, reporting baseline and independent reachability required for promotion." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "public_private_dnp3_disable_all_unsolicited_classes",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "raw capture all selector permutations", "partial/duplicate/other selector and function negatives",
                "direction/fragment/address/CRC/length negatives", "scope and datagram integrity, adjacent rule separation",
                "forged/contradictory evidence, duplicate/reverse time/cooldown, isolation and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R981_PublicDnp3DisableUnsolicitedRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.UdpData(r) || !Research786NetworkEvidence.PublicPrivate(r) ||
                r.SourcePort != 20000 || r.DestinationPort != 20000 || r.L4Len != 24 ||
                !r.Dnp3DisableUnsolicitedObserved || r.Dnp3RestartRequestObserved ||
                r.Dnp3UnsolicitedBinaryEventObserved || r.ApplicationProtocol != "dnp3.disable_unsolicited.request" ||
                r.DnsQname != null || r.DnsIsResponse || r.HttpUri != null || r.HttpMethod != null ||
                r.TlsVersion != null || r.Sni != null) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2717", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "capture_decoded_external_dnp3_disable_all_event_classes", "rule"),
                new DetectionEvidenceItem("outcome", "request_only_approval_acceptance_and_reporting_loss_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "External DNP3 Disable Unsolicited request for all three event classes observed; approval, acceptance and reporting loss unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_dnp3_disable_unsolicited_crc_checked");
                    confidence.AddEvidence(0.35, "public_to_private_control_boundary");
                }, count: 1, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
