// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2714 / AN1908.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R984_PublicFinsDataMemoryClearRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R984", Name: "Public FINS sixteen-word Data Memory clear request", Category: "IotOtAdvanced",
            Description: "Public IPv4 client sends an exact FINS/UDP Memory Area Write request clearing sixteen Data Memory words on a private CPU unit. Authorization, register semantics and write outcome unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R984.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R984", Name = "Public FINS sixteen-word Data Memory clear request", Category = "IotOtAdvanced",
            Description = "workbook.R2714 AN1908: narrow zero-block write request; no unsafe parameter value, accepted write or historian drift inferred.",
            Severity = SeverityLevel.Medium, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow, RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "destination.port", "packet.id", "fins.data_memory_clear.capture" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Complete IPv4 UDP/9600 to UDP/9600, local CPU-unit FINS command 0102, DM word area 82, start <=32752, bit offset zero, exactly 16 zero words." },
            NegativeConditions = new[] { "Other commands/areas/counts/values, response or no-response request, routed/non-CPU or invalid nodes, malformed/incomplete datagram, wrong scope and contradictions fail closed." },
            FalsePositives = new[] { "Approved initialization, recovery or commissioning can clear data memory. Device model, safe ranges, authorized sources and process-state effect required before promotion." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "public_private_fins_data_memory_zero_block",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "raw capture address/node boundaries", "ordinary writes, different area/count/values and other commands",
                "header/routing/length/scope controls", "forged or contradictory fields", "duplicate/reverse time/cooldown, isolation, privacy and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R984_PublicFinsDataMemoryClearRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.UdpData(r) || !Research786NetworkEvidence.PublicPrivate(r) ||
                r.SourcePort != 9600 || r.DestinationPort != 9600 || r.L4Len != 50 ||
                !r.FinsDataMemoryClearObserved || r.FinsNodeNegotiationObserved ||
                r.ApplicationProtocol != "fins.udp.data_memory_clear.request" ||
                r.DnsQname != null || r.DnsIsResponse || r.HttpUri != null || r.HttpMethod != null ||
                r.TlsVersion != null || r.Sni != null) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2714", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "capture_decoded_external_fins_dm_sixteen_zero_words", "rule"),
                new DetectionEvidenceItem("outcome", "request_only_authorization_memory_semantics_and_effect_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "External FINS Data Memory sixteen-word zero-block write request observed; authorization, memory semantics and outcome unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_fins_data_memory_zero_block_request");
                    confidence.AddEvidence(0.35, "public_to_private_control_boundary");
                }, count: 1, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
