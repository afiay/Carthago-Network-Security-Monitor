// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2690 / AN1920.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R977_PublicBacnetObjectListReadRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R977", Name: "Public BACnet Device Object_List read request", Category: "IotOtAdvanced",
            Description: "Public IPv4 client sends an exact BACnet/IP Device Object_List ReadProperty request without array index to private UDP/47808. Returned directory, source authorization and baseline deviation unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R977.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R977", Name = "Public BACnet Device Object_List read request", Category = "IotOtAdvanced",
            Description = "workbook.R2690 AN1920: narrow whole-directory request projection, not completed enumeration or unauthorized discovery.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "destination.port", "packet.id", "bacnet.object_list_read.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Complete IPv4 UDP/47808 Original-Unicast local NPDU, unsegmented ReadProperty service 12, Device object type 8, concrete instance, property 76, no array index." },
            NegativeConditions = new[] { "Other object/property/service, array length or single-index query, ACK, routed/broadcast/segmented or malformed/incomplete datagram, wrong scope and contradictions fail closed." },
            FalsePositives = new[] { "Authorized inventory, commissioning, BMS and engineering diagnostics routinely read Object_List; source policy and operational baseline are prerequisites for promotion." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "public_private_bacnet_device_object_list_read",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "raw capture valid object and header boundaries", "ordinary property and array-index controls",
                "service, object and framing negatives", "scope/datagram completeness and adjacent rule separation",
                "forgery/contradictions, duplicate/cooldown/isolation, privacy and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R977_PublicBacnetObjectListReadRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.UdpData(r) || !Research786NetworkEvidence.PublicPrivate(r) ||
                r.DestinationPort != 47808 || r.L4Len != 17 ||
                !r.BacnetObjectListReadObserved || r.BacnetReinitializeDeviceRequestObserved ||
                r.BacnetWritePropertyRequestObserved || r.BacnetDeviceCommunicationDisableObserved ||
                r.ApplicationProtocol != "bacnet.device.object_list.read" ||
                r.DnsQname != null || r.DnsIsResponse || r.HttpUri != null || r.HttpMethod != null ||
                r.TlsVersion != null || r.Sni != null) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2690", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "capture_decoded_external_bacnet_whole_object_list_read", "rule"),
                new DetectionEvidenceItem("outcome", "request_only_authorization_baseline_and_directory_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "External BACnet Device Object_List read request observed; authorization, baseline deviation and returned directory unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_bacnet_device_object_list_read");
                    confidence.AddEvidence(0.35, "public_to_private_management_boundary");
                }, count: 1, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
