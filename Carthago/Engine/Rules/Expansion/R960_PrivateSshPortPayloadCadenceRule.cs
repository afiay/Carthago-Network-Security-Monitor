// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Original workbook R2812; xUnit source authored first.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R960_PrivateSshPortPayloadCadenceRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R960", Name: "Private SSH-port payload cadence with local tool attribution", Category: "IotOtAdvanced",
            Description: "Same private ssh/plink PID and private peer sends four TCP/22 data records of 512–4096 bytes at 5–20 second intervals. ICS role, approved management baseline, decoded SSH command and authorization are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R960.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R960", Name = "Private SSH-port payload cadence with local tool attribution", Category = "IotOtAdvanced",
            Description = "workbook.R2812: Same private ssh/plink PID and private peer sends four TCP/22 data records of 512–4096 bytes at 5–20 second intervals. ICS role, approved management baseline, decoded SSH command and authorization are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "process.id", "process.name" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Same private ssh/plink PID and private peer sends four TCP/22 data records of 512–4096 bytes at 5–20 second intervals. ICS role, approved management baseline, decoded SSH command and authorization are unknown.", "Coherent typed IPv4 fields and independent bounded UTC observations." },
            NegativeConditions = new[] { "Wrong endpoints, missing or contradictory typed evidence, duplicate IDs, reverse UTC or expired windows fail closed.",
                "No unsupported host action, authenticated session, authorization or security outcome inferred." },
            FalsePositives = new[] { "Authorized administration, maintenance, deployment and diagnostics may share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 4, Window = TimeSpan.FromSeconds(65),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "R960_PrivateSshPortPayloadCadenceRule",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory fields", "duplicate and reverse UTC", "correlation expiry and isolation", "cooldown recovery", "raw Info excluded", "independent state and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research736CadenceWindow _cadence = new();
        public R960_PrivateSshPortPayloadCadenceRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            if (!(Research786NetworkEvidence.Internal(r) && Research786NetworkEvidence.TcpData(r) && r.Source != r.Destination && r.DestinationPort == 22 && Research676Evidence.Process(r, "ssh", "ssh.exe", "plink.exe", "plink") && r.L4Len >= 512 && r.L4Len <= 4096 && r.HttpMethod == null && r.HttpUri == null && r.DnsQname == null && r.TlsVersion == null && r.Sni == null && !r.DnsIsResponse)) return NoMatch();
            if (!_cadence.Observe(r.Source! + "|" + r.Destination! + "|" + r.ProcessId, r.Id, r.L4Len!.Value, context.TimestampUtc, 4, 5, 20, 256, 65)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2812", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "R960_PrivateSshPortPayloadCadenceRule", "rule"),
                new DetectionEvidenceItem("outcome", "typed_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Private SSH-port payload cadence with local tool attribution observed; authorization, causality and outcome remain unverified.", evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "specific_workbook_observable_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 4, windowSeconds: 65);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
