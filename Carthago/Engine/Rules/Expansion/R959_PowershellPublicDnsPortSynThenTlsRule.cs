// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Original workbook R2752; xUnit source authored first.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R959_PowershellPublicDnsPortSynThenTlsRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R959", Name: "PowerShell public DNS-port SYN then same-peer TLS", Category: "Discovery",
            Description: "Same PowerShell PID contacts public TCP/53 then sends TLS/443 data to the same public peer. Test-NetConnection, DNS query, connectivity test intent and authorization are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R959.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R959", Name = "PowerShell public DNS-port SYN then same-peer TLS", Category = "Discovery",
            Description = "workbook.R2752: Same PowerShell PID contacts public TCP/53 then sends TLS/443 data to the same public peer. Test-NetConnection, DNS query, connectivity test intent and authorization are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Tls },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "process.id", "process.name", "tls.version", "tls.sni" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Same PowerShell PID contacts public TCP/53 then sends TLS/443 data to the same public peer. Test-NetConnection, DNS query, connectivity test intent and authorization are unknown.", "Coherent typed IPv4 fields and independent bounded UTC observations." },
            NegativeConditions = new[] { "Wrong endpoints, missing or contradictory typed evidence, duplicate IDs, reverse UTC or expired windows fail closed.",
                "No unsupported host action, authenticated session, authorization or security outcome inferred." },
            FalsePositives = new[] { "Authorized administration, maintenance, deployment and diagnostics may share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "R959_PowershellPublicDnsPortSynThenTlsRule",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory fields", "duplicate and reverse UTC", "correlation expiry and isolation", "cooldown recovery", "raw Info excluded", "independent state and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R959_PowershellPublicDnsPortSynThenTlsRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            var first = Research786NetworkEvidence.PrivatePublic(r) && Research676Evidence.Syn(r) && r.DestinationPort == 53 && r.Sni == null && r.HttpUri == null && !r.DnsIsResponse && Research676Evidence.Process(r, "powershell.exe", "powershell", "pwsh.exe", "pwsh");
            var second = Research786NetworkEvidence.PrivatePublic(r) && Research786NetworkEvidence.TcpData(r) && r.DestinationPort == 443 && !string.IsNullOrWhiteSpace(r.TlsVersion) && !string.IsNullOrWhiteSpace(r.Sni) && r.Sni.Length <= 253 && r.HttpMethod == null && r.HttpUri == null && r.DnsQname == null && !r.DnsIsResponse && Research676Evidence.Process(r, "powershell.exe", "powershell", "pwsh.exe", "pwsh");
            if (!first && !second) return NoMatch();
            var key = r.Source! + "|" + r.Destination! + "|" + r.ProcessId;
            if (!_stages.Observe(key, r.Id, context.TimestampUtc, first, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2752", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "R959_PowershellPublicDnsPortSynThenTlsRule", "rule"),
                new DetectionEvidenceItem("outcome", "typed_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "PowerShell public DNS-port SYN then same-peer TLS observed; authorization, causality and outcome remain unverified.", evidence,
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
