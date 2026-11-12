// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Test source authored first; no build/test execution. workbook.R2239.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R908_PublicSmbSynThenParsedWriteRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R908", Name: "Public SMB SYN then same-flow parsed WRITE", Category: "LateralMovement",
            Description: "Public TCP/445 SYN to private host followed by parsed SMB2 WRITE on the same source port. Admin share, account, filename and write success are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R908.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R908", Name = "Public SMB SYN then same-flow parsed WRITE", Category = "LateralMovement",
            Description = "workbook.R2239: Public TCP/445 SYN to private host followed by parsed SMB2 WRITE on the same source port. Admin share, account, filename and write success are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "tcp.flags", "application.protocol", "smb2.complete_write", "smb2.write_length" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Require capture-attested complete standalone SMB2 WRITE with nonzero session/tree/file identifiers and in-bounds data; not a label alone.", "Public TCP/445 SYN to private host followed by parsed SMB2 WRITE on the same source port. Admin share, account, filename and write success are unknown.", "Coherent typed IPv4 fields and bounded UTC observations." },
            NegativeConditions = new[] { "Missing or contradictory evidence, mismatched keys, duplicate packet IDs, reverse UTC and expired windows fail closed.",
                "No unsupported host identity, execution, authentication, authorization or security outcome inferred." },
            FalsePositives = new[] { "Authorized administration, diagnostics, software deployment, maintenance and security testing can share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "R908_PublicSmbSynThenParsedWriteRule",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory fields", "duplicate and reverse UTC",
                "correlation expiry and key isolation", "cooldown recovery", "raw Info exclusion", "neighbor independence", "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R908_PublicSmbSynThenParsedWriteRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            var first = Research786NetworkEvidence.PublicPrivate(r) && r.DestinationPort == 445 && Research676Evidence.Syn(r) && r.Sni == null && r.HttpUri == null && !r.DnsIsResponse;
            var second = Research786NetworkEvidence.PublicPrivate(r) && r.DestinationPort == 445 && Research786NetworkEvidence.TcpData(r) && r.HttpMethod == null && r.HttpUri == null && r.DnsQname == null && r.TlsVersion == null && r.Sni == null && !r.DnsIsResponse && Smb2QualifiedEvidence.Write(r);
            if (!first && !second) return NoMatch();
            var key = r.Source! + "|" + r.Destination! + "|" + r.SourcePort;
            if (!_stages.Observe(key, r.Id, context.TimestampUtc, first, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2239", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "R908_PublicSmbSynThenParsedWriteRule", "rule"),
                new DetectionEvidenceItem("outcome", "typed_network_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Public SMB SYN then same-flow parsed WRITE observed; authorization, causality and outcome remain unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "capture_attested_complete_smb2_write");
                    confidence.AddEvidence(0.33, "specific_workbook_observable_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 2, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
