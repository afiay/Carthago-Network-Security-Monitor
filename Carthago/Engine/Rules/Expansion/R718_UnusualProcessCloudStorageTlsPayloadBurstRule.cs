// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R1330.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R718_UnusualProcessCloudStorageTlsPayloadBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R718",
            Name: "PowerShell or Office process TLS payload burst to cloud storage",
            Category: "ExfiltrationAdvanced",
            Description: "A PowerShell or Office process is associated with four substantial TLS payload observations to a known cloud-storage SNI within two minutes. Packet lengths are not unique transferred bytes and do not prove an upload, file access, authentication, or exfiltration.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R718.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R718",
            Name = "PowerShell or Office process TLS payload burst to cloud storage",
            Category = "ExfiltrationAdvanced",
            Description = "Workbook R1330: the workbook requires large local-file reads followed by high-volume HTTPS uploads. Carthago lacks file-read and decrypted HTTP evidence, so this candidate keeps only unusual process identity, cloud-storage SNI, and a bounded TLS payload burst.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Tls, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "tls.sni", "tls.version", "process.name", "process.id", "l4.length" },
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
            FalsePositives = new[] { "Approved document synchronization, cloud-drive migration, backup, Office collaboration, PowerShell automation, and DLP testing can generate similar TLS bursts." },
            MinimumConfidence = 81,
            WindowThreshold = 4,
            Window = TimeSpan.FromSeconds(120),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+process+cloud_storage_sni+payload_burst",
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

        public R718_UnusualProcessCloudStorageTlsPayloadBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research716Evidence.OutboundTls443(r)
                || !Research716Evidence.Process(r, "powershell.exe", "pwsh.exe", "excel.exe", "winword.exe")
                || !Research716Evidence.CloudStorageHost(r.Sni)
                || r.L4Len is null or < 900 or > 8192
                || !_timed.Observe(r.Source + "|" + r.Sni + "|" + r.ProcessId,
                    r.Id, r.L4Len.Value, context.TimestampUtc, 4, false, 6000))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1330", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "unusual_process_cloud_storage_tls_payload_burst", "rule"),
                new DetectionEvidenceItem("outcome", "cloud_storage_tls_payload_burst_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "PowerShell/Office process cloud-storage TLS payload burst observed; upload direction, unique bytes, file source, and exfiltration are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 4,
                windowSeconds: 120);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
