// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. workbook.R1067; xUnit source authored first.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R934_MqttBrokerTlsDifferentPublicPeersRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R934", Name: "MQTT client TLS to distinct public broker peers", Category: "IotOt",
            Description: "Same private mosquitto_pub PID sends TLS/8883 to two distinct public peers within 45s. Broker trust-root changes, broker identity, MQTT session and policy are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R934.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R934", Name = "MQTT client TLS to distinct public broker peers", Category = "IotOt",
            Description = "workbook.R1067: Same private mosquitto_pub PID sends TLS/8883 to two distinct public peers within 45s. Broker trust-root changes, broker identity, MQTT session and policy are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Tls },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "tcp.flags", "process.id", "process.name", "tls.version" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Same private mosquitto_pub PID sends TLS/8883 to two distinct public peers within 45s. Broker trust-root changes, broker identity, MQTT session and policy are unknown.", "Coherent typed IPv4 fields and independent bounded UTC observations." },
            NegativeConditions = new[] { "Wrong endpoints, missing or contradictory typed evidence, duplicate IDs, reverse UTC or expired windows fail closed.",
                "No unsupported endpoint action, authenticated session, authorization or security outcome inferred." },
            FalsePositives = new[] { "Authorized administration, maintenance, deployment and diagnostics may share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "R934_MqttBrokerTlsDifferentPublicPeersRule",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory fields", "duplicate and reverse UTC", "correlation expiry and isolation", "cooldown recovery", "raw Info excluded", "independent state and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research706DistinctWindow _distinct = new();
        public R934_MqttBrokerTlsDifferentPublicPeersRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            if (!(Research786NetworkEvidence.TcpData(r) && Research786NetworkEvidence.PrivatePublic(r) && r.DestinationPort == 8883 && Research676Evidence.Process(r, "mosquitto_pub", "mosquitto_pub.exe") && !string.IsNullOrWhiteSpace(r.TlsVersion) && !string.IsNullOrWhiteSpace(r.Sni) && r.Sni.Length <= 253 && r.HttpMethod == null && r.HttpUri == null && r.DnsQname == null && !r.DnsIsResponse)) return NoMatch();
            if (!_distinct.Observe(r.Source! + "|" + r.ProcessId, r.Destination!, r.Id, context.TimestampUtc, 2, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture), r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1067", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "R934_MqttBrokerTlsDifferentPublicPeersRule", "rule"),
                new DetectionEvidenceItem("outcome", "typed_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "MQTT client TLS to distinct public broker peers observed; authorization, causality and outcome remain unverified.", evidence,
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
