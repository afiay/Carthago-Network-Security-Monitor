// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. workbook.R1079; xUnit source authored first.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R933_MqttSynThenRetainedPublishRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R933", Name: "MQTT private client SYN then retained PUBLISH", Category: "IotOt",
            Description: "Private client TCP/1883 SYN to private broker followed by same-flow parsed retained control-topic PUBLISH. Reconnection, delivery, command application and device response are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R933.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R933", Name = "MQTT private client SYN then retained PUBLISH", Category = "IotOt",
            Description = "workbook.R1079: Private client TCP/1883 SYN to private broker followed by same-flow parsed retained control-topic PUBLISH. Reconnection, delivery, command application and device response are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "tcp.flags" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Private client TCP/1883 SYN to private broker followed by same-flow parsed retained control-topic PUBLISH. Reconnection, delivery, command application and device response are unknown.", "Coherent typed IPv4 fields and independent bounded UTC observations." },
            NegativeConditions = new[] { "Wrong endpoints, missing or contradictory typed evidence, duplicate IDs, reverse UTC or expired windows fail closed.",
                "No unsupported endpoint action, authenticated session, authorization or security outcome inferred." },
            FalsePositives = new[] { "Authorized administration, maintenance, deployment and diagnostics may share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "R933_MqttSynThenRetainedPublishRule",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory fields", "duplicate and reverse UTC", "correlation expiry and isolation", "cooldown recovery", "raw Info excluded", "independent state and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R933_MqttSynThenRetainedPublishRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            var first = Research676Evidence.Syn(r) && Research786NetworkEvidence.Internal(r) && r.DestinationPort == 1883 && r.Sni == null && r.HttpUri == null && !r.DnsIsResponse && r.Source != r.Destination;
            var second = Research786NetworkEvidence.TcpData(r) && Research786NetworkEvidence.Internal(r) && r.Source != r.Destination && r.DestinationPort == 1883 && r.MqttPublishTopicObserved && r.MqttControlTopicObserved && r.MqttRetain == true && r.HttpMethod == null && r.HttpUri == null && r.DnsQname == null && r.TlsVersion == null && r.Sni == null && !r.DnsIsResponse;
            if (!first && !second) return NoMatch();
            var key = r.Source! + "|" + r.Destination! + "|" + r.SourcePort;
            if (!_stages.Observe(key, r.Id, context.TimestampUtc, first, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1079", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "R933_MqttSynThenRetainedPublishRule", "rule"),
                new DetectionEvidenceItem("outcome", "typed_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "MQTT private client SYN then retained PUBLISH observed; authorization, causality and outcome remain unverified.", evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "specific_workbook_observable_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 2, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
