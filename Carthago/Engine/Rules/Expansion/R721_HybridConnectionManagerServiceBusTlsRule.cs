// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R2321.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R721_HybridConnectionManagerServiceBusTlsRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R721",
            Name: "Hybrid Connection Manager TLS SNI to Azure Service Bus",
            Category: "EvasionTunnel",
            Description: "HybridConnectionManager.exe is associated with outbound TLS to a servicebus.windows.net SNI. Service state, Hybrid Connection configuration, authentication, successful relay establishment, and malicious intent are not observed.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R721.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R721",
            Name = "Hybrid Connection Manager TLS SNI to Azure Service Bus",
            Category = "EvasionTunnel",
            Description = "Workbook R2321: the source Sigma rule is a Service Bus client event indicating Hybrid Connection Manager activity. Carthago lacks that service-event producer; this rule is deliberately limited to the exact local process plus TLS SNI, and is distinct from R629's DNS-only observation.",
            Severity = SeverityLevel.Low,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Tls, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "tls.sni", "tls.version", "process.name", "process.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed packet, parser, and best-effort process fields for this exact independent predicate.",
                "Multi-observation rules use bounded unique packet IDs with UTC ordering and a fixed rule-owned window.",
                "Only the observable network/request/process association is claimed; endpoint or server outcome is not inferred."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, and free-form Info-only indicators.",
                "Reject duplicate packet IDs, stale/out-of-order observations, and cooldown repeats.",
                "Do not infer authentication, command-line arguments, file reads/writes, transfer completion, exploit success, or compromise."
            },
            FalsePositives = new[] { "Legitimate Azure Hybrid Connection Manager deployments are expected to contact Azure Service Bus and are the primary false-positive case." },
            MinimumConfidence = 76,
            WindowThreshold = 1,
            Window = TimeSpan.FromSeconds(300),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+hybridconnectionmanager_pid+servicebus_sni",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive real-life-shaped case and benign near miss",
                "wrong or missing telemetry and contradictory protocol fields",
                "duplicate packet ID and out-of-order timestamp where relevant",
                "window expiry and cooldown behavior",
                "privacy/redaction, registry uniqueness, Candidate Shadow, and non-convergence"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();

        public R721_HybridConnectionManagerServiceBusTlsRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research716Evidence.OutboundTls443(r)
                || !Research716Evidence.Process(r, "hybridconnectionmanager.exe")
                || !Research716Evidence.HostIs(r.Sni, "servicebus.windows.net"))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2321", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "hybridconnectionmanager_servicebus_tls_sni", "rule"),
                new DetectionEvidenceItem("outcome", "servicebus_tls_contact_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Low,
                "Hybrid Connection Manager TLS contact to Azure Service Bus observed; relay configuration, authentication, and session outcome are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 1,
                windowSeconds: 300);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
