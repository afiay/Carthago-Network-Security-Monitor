// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2697 / AN1933.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R975_PublicBacnetReinitializeDeviceRequestRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R975", Name: "Public BACnet coldstart or warmstart request", Category: "IotOtAdvanced",
            Description: "Public IPv4 source sends a capture-validated BACnet/IP unsegmented ReinitializeDevice coldstart/warmstart request to private UDP/47808. Approval, authentication and restart outcome unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R975.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R975", Name = "Public BACnet coldstart or warmstart request", Category = "IotOtAdvanced",
            Description = "workbook.R2697 AN1933: narrow BACnet restart-command projection, not the SIPROTEC exploit, authorized-source analysis or verified device outage.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "destination.port", "packet.id", "bacnet.reinitialize_device.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Complete IPv4 UDP/47808 Original-Unicast BVLC local NPDU, unsegmented ConfirmedRequest service 20, one context [0] enum coldstart 0 or warmstart 1, no password." },
            NegativeConditions = new[] { "Other BACnet services/states, ACKs, routing/broadcast/segmentation, password-bearing or malformed/incomplete datagrams, wrong scope and contradictory evidence fail closed." },
            FalsePositives = new[] { "Approved vendor maintenance, recovery and commissioning may legitimately send restart commands across routed management paths." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "public_private_bacnet_reinitialize_device",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "raw capture cold/warm positives", "service/state/framing controls",
                "scope and datagram integrity", "forged/contradictory evidence and adjacent rule separation",
                "duplicate/reverse time/cooldown, peer isolation, privacy and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R975_PublicBacnetReinitializeDeviceRequestRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.UdpData(r) || !Research786NetworkEvidence.PublicPrivate(r) ||
                r.DestinationPort != 47808 || r.L4Len != 12 ||
                !r.BacnetReinitializeDeviceRequestObserved ||
                r.BacnetWritePropertyRequestObserved || r.BacnetDeviceCommunicationDisableObserved ||
                r.ApplicationProtocol != "bacnet.reinitialize_device.request" ||
                r.DnsQname != null || r.DnsIsResponse || r.HttpUri != null || r.HttpMethod != null ||
                r.TlsVersion != null || r.Sni != null) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2697", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "capture_decoded_bacnet_cold_or_warm_restart_request", "rule"),
                new DetectionEvidenceItem("outcome", "request_only_approval_and_device_restart_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "External BACnet coldstart or warmstart request observed; approval and device restart outcome unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_bacnet_reinitialize_request");
                    confidence.AddEvidence(0.35, "public_to_private_control_boundary");
                }, count: 1, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
