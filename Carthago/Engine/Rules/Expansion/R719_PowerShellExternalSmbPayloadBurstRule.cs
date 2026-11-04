// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R1373.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R719_PowerShellExternalSmbPayloadBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R719",
            Name: "PowerShell process raw SMB-port payload burst to public host",
            Category: "ExfiltrationAdvanced",
            Description: "A PowerShell process produces three raw TCP payload observations to a public TCP/445 peer within two minutes. SMB authentication, share access, file transfer, unique byte counts, and exfiltration are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R719.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R719",
            Name = "PowerShell process raw SMB-port payload burst to public host",
            Category = "ExfiltrationAdvanced",
            Description = "Workbook R1373: the workbook describes unusual alternate-protocol file transfer over FTP/SMB/SMTP/DNS. This independent rule narrows that broad behavior to PowerShell-attributed outbound public SMB-port payload observations only.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "tcp", "destination.port", "process.name", "process.id", "l4.length" },
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
            FalsePositives = new[] { "Approved cross-boundary SMB gateways, administrative PowerShell modules, backup tooling, and security tests can use external TCP/445." },
            MinimumConfidence = 82,
            WindowThreshold = 3,
            Window = TimeSpan.FromSeconds(120),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+powershell_pid+public_smb_peer+payload_burst",
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
        private readonly Research666TimedWindow _timed = new();

        public R719_PowerShellExternalSmbPayloadBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research676Evidence.Tcp(r)
                || !Research676Evidence.PrivateToPublic(r)
                || r.DestinationPort != 445
                || !Research716Evidence.Process(r, "powershell.exe", "pwsh.exe")
                || r.L4Len is null or < 80 or > 4096
                || r.HttpMethod != null || r.DnsQname != null || r.TlsVersion != null
                || (r.ApplicationProtocol != null
                    && !r.ApplicationProtocol.StartsWith("smb", StringComparison.OrdinalIgnoreCase))
                || !_timed.Observe(r.Source + "|" + r.Destination + "|" + r.ProcessId,
                    r.Id, r.L4Len.Value, context.TimestampUtc, 3, false, 600))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1373", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "powershell_public_tcp445_payload_burst", "rule"),
                new DetectionEvidenceItem("outcome", "external_smb_payload_observations_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "PowerShell-attributed public TCP/445 payload burst observed; SMB authentication, file transfer, unique bytes, and exfiltration are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 3,
                windowSeconds: 120);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
