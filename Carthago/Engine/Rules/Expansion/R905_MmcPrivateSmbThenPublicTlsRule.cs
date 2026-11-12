// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero builds/tests executed. workbook.R1764.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R905_MmcPrivateSmbThenPublicTlsRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R905", Name: "MMC private SMB SYN then public TLS data", Category: "EvasionInfra",
            Description: "Same private source and mmc PID initiate TCP/445 to a private peer then TLS-marked TCP/443 data to a public peer within 45s; MMC document loading, COM activation, DLL loading and causality are not observed.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R905.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R905", Name = "MMC private SMB SYN then public TLS data", Category = "EvasionInfra",
            Description = "workbook.R1764: Same private source and mmc PID initiate TCP/445 to a private peer then TLS-marked TCP/443 data to a public peer within 45s; MMC document loading, COM activation, DLL loading and causality are not observed.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Tls },
            RequiredFields = new[] { "source", "destination", "destination.port", "tcp.flags", "packet.id", "process.id", "process.name", "tls.sni", "tls.version" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Coherent typed IPv4 packet and specific process attribution where required.", "Ordered independent UTC observations where correlation applies." },
            NegativeConditions = new[] { "Missing or contradictory typed evidence, wrong endpoint, duplicate IDs, reverse UTC and expired correlation fail closed.",
                "No unsupported authentication, execution, file access, authorization or causality inferred." },
            FalsePositives = new[] { "Approved administration, diagnostics, maintenance and software deployment can match." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "mmc_private_smb445_then_public_tls443",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory evidence",
                "duplicate IDs and reverse UTC", "correlation expiry and key isolation where applicable", "cooldown recovery",
                "raw Info exclusion", "neighbor independence", "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R905_MmcPrivateSmbThenPublicTlsRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r) || !Research676Evidence.Process(r, "mmc.exe", "mmc")
                || r.HttpMethod != null || r.HttpUri != null || r.DnsQname != null || r.DnsIsResponse) return NoMatch();
            var first = Research786NetworkEvidence.Internal(r) && r.Source != r.Destination
                && Research676Evidence.Syn(r) && r.DestinationPort == 445 && r.Sni == null;
            var second = Research786NetworkEvidence.PrivatePublic(r) && Research786NetworkEvidence.TcpData(r)
                && r.DestinationPort == 443 && !string.IsNullOrWhiteSpace(r.TlsVersion)
                && !string.IsNullOrWhiteSpace(r.Sni) && r.Sni.Length <= 253;
            if (!first && !second) return NoMatch();
            var key = r.Source! + "|" + r.ProcessId;
            if (!_stages.Observe(key, r.Id, context.TimestampUtc, first, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1764", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "mmc_private_smb445_then_public_tls443", "rule"),
                new DetectionEvidenceItem("outcome", "typed_network_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "MMC private SMB SYN then public TLS data observed; authorization, causality and security outcome remain unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "source_specific_workbook_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 2, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
