// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook workbook.R1810.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R735_EsxiProcessWebProtocolPortMismatchRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R735",
            Name: "ESXi process HTTP/TLS service-port mismatch",
            Category: "EvasionInfra",
            Description: "hostd, vpxa, or vmx is associated with parsed HTTP on VMware service ports 902/903 or TLS on cleartext web ports 80/8000/8080. Certificate validity, payload impersonation, malicious tunneling and compromise are not observed.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R735.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R735",
            Name = "ESXi process HTTP/TLS service-port mismatch",
            Category = "EvasionInfra",
            Description = "workbook.R1810: the source analytic describes protocol/service impersonation using anomalous TLS, HTTP headers and port mismatch on ESXi. Carthago lacks certificate-validation and platform audit context, so this candidate requires only exact ESXi process attribution plus a typed HTTP/TLS port mismatch.",
            Severity = SeverityLevel.Low,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Tls, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "destination.port", "process.name", "process.id", "application_protocol_or_tls" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed packet fields plus the exact process/network predicate defined by this independent candidate.",
                "Correlated rules accept only unique packet IDs in monotonic UTC order inside a bounded rule-owned window.",
                "Only the observed process association, network shape, request classification or packet burst is asserted."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, invalid endpoints and free-form Info-only assertions.",
                "Reject duplicate packet IDs, reverse time, expired windows and cooldown repeats.",
                "Do not infer command-line arguments, asset role, file access, successful transfer, authenticated endpoint state, C2, DoS impact, exploit success or compromise."
            },
            FalsePositives = new[] { "Custom reverse proxies, vendor diagnostics, non-default management configuration and lab/test environments can intentionally place HTTP or TLS on unusual service ports." },
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromSeconds(300),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+esxi_process+peer+typed_protocol_port_mismatch",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive real-life-shaped sample and benign near miss",
                "missing and contradictory telemetry",
                "duplicate ID, reverse time and window expiry for correlated candidates",
                "cooldown suppression and recovery",
                "fixed evidence privacy, Candidate Shadow and unique registry"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();

        public R735_EsxiProcessWebProtocolPortMismatchRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research726Evidence.EsxiPortProtocolMismatch(r))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1810", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "esxi_process_typed_http_tls_port_mismatch", "rule"),
                new DetectionEvidenceItem("outcome", "protocol_port_mismatch_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Low,
                "ESXi process typed HTTP/TLS service-port mismatch observed; certificate validity, impersonation intent, tunnel behavior and compromise are unknown.",
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
