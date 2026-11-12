// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero builds/tests executed. workbook.R1321.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R903_PowershellSmbWriteThenWinRmSynRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R903", Name: "PowerShell private SMB2 WRITE then WinRM SYN", Category: "LateralMovement",
            Description: "Same private source and PowerShell PID send a parsed SMB2 WRITE request to TCP/445 then a TCP/5985 SYN to that private peer within 45s; file creation, transfer completion, authenticated WinRM and execution are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R903.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R903", Name = "PowerShell private SMB2 WRITE then WinRM SYN", Category = "LateralMovement",
            Description = "workbook.R1321: Same private source and PowerShell PID send a parsed SMB2 WRITE request to TCP/445 then a TCP/5985 SYN to that private peer within 45s; file creation, transfer completion, authenticated WinRM and execution are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "destination.port", "tcp.flags", "application.protocol", "packet.id", "process.id", "process.name", "smb2.complete_write", "smb2.write_length" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Require capture-attested complete standalone SMB2 WRITE with nonzero session/tree/file identifiers and in-bounds data; not a label alone.", "Coherent typed IPv4 packet and specific process attribution where required.", "Ordered independent UTC observations where correlation applies." },
            NegativeConditions = new[] { "Missing or contradictory typed evidence, wrong endpoint, duplicate IDs, reverse UTC and expired correlation fail closed.",
                "No unsupported authentication, execution, file access, authorization or causality inferred." },
            FalsePositives = new[] { "Approved administration, diagnostics, maintenance and software deployment can match." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "powershell_private_smb2_write_then_winrm5985_syn",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory evidence",
                "duplicate IDs and reverse UTC", "correlation expiry and key isolation where applicable", "cooldown recovery",
                "raw Info exclusion", "neighbor independence", "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R903_PowershellSmbWriteThenWinRmSynRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r) || !Research786NetworkEvidence.Internal(r)
                || !Research676Evidence.Process(r, "powershell.exe", "powershell", "pwsh.exe", "pwsh")
                || r.Source == r.Destination || r.Sni != null || r.HttpUri != null || r.DnsIsResponse) return NoMatch();
            var first = Research786NetworkEvidence.TcpData(r) && r.DestinationPort == 445
                && Smb2QualifiedEvidence.Write(r)
                && r.HttpMethod == null && r.DnsQname == null && r.TlsVersion == null;
            var second = Research676Evidence.Syn(r) && r.DestinationPort == 5985;
            if (!first && !second) return NoMatch();
            var key = r.Source! + "|" + r.Destination! + "|" + r.ProcessId;
            if (!_stages.Observe(key, r.Id, context.TimestampUtc, first, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1321", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "powershell_private_smb2_write_then_winrm5985_syn", "rule"),
                new DetectionEvidenceItem("outcome", "typed_network_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "PowerShell private SMB2 WRITE then WinRM SYN observed; authorization, causality and security outcome remain unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "capture_attested_complete_smb2_write");
                    confidence.AddEvidence(0.33, "source_specific_workbook_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 2, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
