// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2781, AN2236.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R967_PublicDnp3UnsolicitedBinaryEventRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R967", Name: "Public-source DNP3 unsolicited binary event response", Category: "IotOtAdvanced",
            Description: "Public IPv4 source sends a capture-validated DNP3 unsolicited binary-input event response to a private UDP/20000 peer. Device enrollment, authenticity, point identity and spoofing are unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R967.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R967", Name = "Public-source DNP3 unsolicited binary event response", Category = "IotOtAdvanced",
            Description = "workbook.R2781 AN2236: narrow DNP3 unsolicited response observation; no enrolled point/device binding or claim of spoofing.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "dnp3.unsolicited_binary_event.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Complete IPv4 UDP DNP3 link frame, valid header and data CRCs, one unsolicited application fragment with indexed group 2 variation 1 events." },
            NegativeConditions = new[] { "Solicited and null unsolicited responses, requests, unsupported object formats, malformed CRC/fragments, wrong scope and missing capture evidence fail closed." },
            FalsePositives = new[] { "Legitimate externally routed outstations, vendor test networks and authorized remote monitoring may match." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "public_source_private_peer_dnp3_unsolicited_binary_event",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "raw capture and CRC known vector", "solicited/null benign controls", "malformed CRC and frame/object boundaries",
                "missing/contradictory evidence and direction", "duplicate/reverse UTC, cooldown recovery, peer/instance isolation", "privacy and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R967_PublicDnp3UnsolicitedBinaryEventRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.UdpData(r) || !Research786NetworkEvidence.PublicPrivate(r) ||
                r.SourcePort != 20000 || r.DestinationPort != 20000 ||
                !r.Dnp3UnsolicitedBinaryEventObserved || r.ApplicationProtocol != "dnp3.unsolicited.binary_event" ||
                r.DnsQname != null || r.DnsIsResponse || r.HttpUri != null || r.HttpMethod != null ||
                r.TlsVersion != null || r.Sni != null) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2781", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "capture_decoded_external_dnp3_unsolicited_binary_event", "rule"),
                new DetectionEvidenceItem("outcome", "response_only_enrollment_and_authenticity_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "External DNP3 unsolicited binary-event response observed; source enrollment, authenticity and spoofing unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_dnp3_frame_and_application_structure");
                    confidence.AddEvidence(0.35, "public_to_private_reporting_boundary");
                }, count: 1, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
