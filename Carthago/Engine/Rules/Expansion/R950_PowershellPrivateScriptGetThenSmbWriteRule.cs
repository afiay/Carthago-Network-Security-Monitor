// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Original workbook R1328; xUnit source authored first.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R950_PowershellPrivateScriptGetThenSmbWriteRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R950", Name: "PowerShell private PS1 GET then parsed SMB2 WRITE", Category: "LateralMovement",
            Description: "Same private PowerShell PID retrieves a .ps1 path over private HTTP then issues a parsed SMB2 WRITE to the same private peer. GPO, logon script setting, file contents, user logon and execution are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R950.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R950", Name = "PowerShell private PS1 GET then parsed SMB2 WRITE", Category = "LateralMovement",
            Description = "workbook.R1328: Same private PowerShell PID retrieves a .ps1 path over private HTTP then issues a parsed SMB2 WRITE to the same private peer. GPO, logon script setting, file contents, user logon and execution are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Http },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "process.id", "process.name", "http.method", "http.uri", "http.host", "application.protocol", "smb2.complete_write", "smb2.write_length" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Require capture-attested complete standalone SMB2 WRITE with nonzero session/tree/file identifiers and in-bounds data; not a label alone.", "Same private PowerShell PID retrieves a .ps1 path over private HTTP then issues a parsed SMB2 WRITE to the same private peer. GPO, logon script setting, file contents, user logon and execution are unknown.", "Coherent typed IPv4 fields and independent bounded UTC observations." },
            NegativeConditions = new[] { "Wrong endpoints, missing or contradictory typed evidence, duplicate IDs, reverse UTC or expired windows fail closed.",
                "No unsupported host action, authenticated session, authorization or security outcome inferred." },
            FalsePositives = new[] { "Authorized administration, maintenance, deployment and diagnostics may share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "R950_PowershellPrivateScriptGetThenSmbWriteRule",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory fields", "duplicate and reverse UTC", "correlation expiry and isolation", "cooldown recovery", "raw Info excluded", "independent state and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R950_PowershellPrivateScriptGetThenSmbWriteRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            var first = Research786NetworkEvidence.Internal(r) && Research786NetworkEvidence.TcpData(r) && r.DestinationPort == 80 && Research676Evidence.Process(r, "powershell.exe", "powershell", "pwsh.exe", "pwsh") && WebSignatureRequestEvidence.TryGet(r, out var method, out var uri) && method == "GET" && (uri.Split('?')[0].EndsWith(".ps1", StringComparison.OrdinalIgnoreCase)) && !string.IsNullOrWhiteSpace(r.HttpHost) && r.HttpHost.Length <= 253 && r.Source != r.Destination;
            var second = Research786NetworkEvidence.Internal(r) && Research786NetworkEvidence.TcpData(r) && Research676Evidence.Process(r, "powershell.exe", "powershell", "pwsh.exe", "pwsh") && r.Source != r.Destination && r.DestinationPort == 445 && Smb2QualifiedEvidence.Write(r) && r.HttpMethod == null && r.HttpUri == null && r.DnsQname == null && r.TlsVersion == null && r.Sni == null && !r.DnsIsResponse;
            if (!first && !second) return NoMatch();
            var key = r.Source! + "|" + r.Destination! + "|" + r.ProcessId;
            if (!_stages.Observe(key, r.Id, context.TimestampUtc, first, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1328", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "R950_PowershellPrivateScriptGetThenSmbWriteRule", "rule"),
                new DetectionEvidenceItem("outcome", "typed_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "PowerShell private PS1 GET then parsed SMB2 WRITE observed; authorization, causality and outcome remain unverified.", Smb2QualifiedEvidence.WithTarget(evidence, r),
                confidence =>
                {
                    confidence.AddEvidence(0.45, "capture_attested_complete_smb2_write");
                    confidence.AddEvidence(0.33, "specific_workbook_observable_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 2, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
