// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2711 / AN1861.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R979_PublicBacnetEventDisableRequestRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R979", Name: "Public BACnet Event_Enable all-transition disable request", Category: "IotOtAdvanced",
            Description: "Public IPv4 client sends exact BACnet WriteProperty Event_Enable all-zero three-bit request to a private Analog Input or Binary Input object. Authorization, acceptance and alarm-state impact unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R979.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R979", Name = "Public BACnet Event_Enable all-transition disable request", Category = "IotOtAdvanced",
            Description = "workbook.R2711 AN1861: narrow notification-disable request evidence, not observed alarm suppression or historian correlation.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "destination.port", "packet.id", "bacnet.event_disable.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Complete IPv4 UDP/47808 Original-Unicast local NPDU, unsegmented WriteProperty service 15, Analog Input or Binary Input concrete object, Event_Enable property 35, exact application bit string with five unused bits and all three transitions zero." },
            NegativeConditions = new[] { "Enabled/partially enabled notifications, other object/property/service, array index/priority, wrong bit-string length/padding/type, malformed/routed/broadcast/segmented traffic and contradictory evidence fail closed." },
            FalsePositives = new[] { "Authorized commissioning, planned maintenance and engineering changes can disable notifications; operator, change-control and alarm-state effect required before promotion." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "public_private_bacnet_event_enable_all_zero",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "raw positive captures and object boundaries", "partial enable/other property and bit-string shape negatives",
                "datagram/scope, adjacent scalar write and restart separation", "forged/contradictory evidence", "duplicate/reverse time/cooldown, isolation, privacy and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R979_PublicBacnetEventDisableRequestRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.UdpData(r) || !Research786NetworkEvidence.PublicPrivate(r) ||
                r.DestinationPort != 47808 || r.L4Len != 22 ||
                !r.BacnetEventDisableRequestObserved || r.BacnetObjectListReadObserved ||
                r.BacnetReinitializeDeviceRequestObserved || r.BacnetWritePropertyRequestObserved ||
                r.BacnetDeviceCommunicationDisableObserved ||
                r.ApplicationProtocol != "bacnet.event_enable.disable_all.request" ||
                r.DnsQname != null || r.DnsIsResponse || r.HttpUri != null || r.HttpMethod != null ||
                r.TlsVersion != null || r.Sni != null) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2711", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "capture_decoded_external_bacnet_event_enable_all_zero", "rule"),
                new DetectionEvidenceItem("outcome", "request_only_approval_acceptance_and_alarm_state_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "External BACnet Event_Enable all-transition disable request observed; approval, acceptance and alarm-state impact unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_bacnet_event_enable_bit_string_write");
                    confidence.AddEvidence(0.35, "public_to_private_control_boundary");
                }, count: 1, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
