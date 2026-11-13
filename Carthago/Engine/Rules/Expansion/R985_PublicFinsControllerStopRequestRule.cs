// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2721 / AN1887.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R985_PublicFinsControllerStopRequestRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R985", Name: "Public FINS controller STOP request", Category: "IotOtAdvanced",
            Description: "Public IPv4 client sends an exact FINS/UDP STOP request to a private CPU unit. Approval, acceptance and controller mode unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R985.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R985", Name = "Public FINS controller STOP request", Category = "IotOtAdvanced",
            Description = "workbook.R2721 AN1887: narrow controller mode-change command; no actual mode transition or unauthorized action inferred.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "destination.port", "packet.id", "fins.controller_stop.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Complete IPv4 UDP/9600-to-9600, exact 12-byte local CPU FINS command 0402, response requested, distinct nodes 1–254, no command parameters." },
            NegativeConditions = new[] { "RUN, memory operations, responses, no-response requests, routed/non-CPU units, invalid nodes, trailing/truncated data, wrong scope and contradictory evidence fail closed." },
            FalsePositives = new[] { "Approved engineering, commissioning and maintenance can stop a controller. Source policy, change-control and mode-state evidence required before promotion." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "public_private_fins_controller_stop",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "raw capture node/SID boundaries", "other commands and header/framing controls",
                "scope and datagram integrity", "adjacent FINS write separation and forged evidence",
                "duplicate/reverse time/cooldown, isolation, privacy and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R985_PublicFinsControllerStopRequestRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.UdpData(r) || !Research786NetworkEvidence.PublicPrivate(r) ||
                r.SourcePort != 9600 || r.DestinationPort != 9600 || r.L4Len != 12 ||
                !r.FinsControllerStopObserved || r.FinsNodeNegotiationObserved || r.FinsDataMemoryClearObserved ||
                r.ApplicationProtocol != "fins.udp.controller_stop.request" ||
                r.DnsQname != null || r.DnsIsResponse || r.HttpUri != null || r.HttpMethod != null ||
                r.TlsVersion != null || r.Sni != null) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2721", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "capture_decoded_external_fins_controller_stop_request", "rule"),
                new DetectionEvidenceItem("outcome", "request_only_approval_acceptance_and_mode_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "External FINS controller STOP request observed; authorization, acceptance and controller mode unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_fins_controller_stop_request");
                    confidence.AddEvidence(0.35, "public_to_private_control_boundary");
                }, count: 1, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
