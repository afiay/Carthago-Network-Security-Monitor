// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; no tests or builds executed. workbook.R1204.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R852_PowershellCloudTlsPayloadBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R852", Name: "PowerShell Dropbox-content TLS payload burst", Category: "Exfiltration",
            Description: "Five same-PID outbound PowerShell TCP/443 payload packets of >=1200 bytes to content.dropboxapi.com SNI in 30s; no decrypted upload, account identity, file or exfiltration established.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R852.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R852", Name = "PowerShell Dropbox-content TLS payload burst", Category = "Exfiltration",
            Description = "workbook.R1204: Five same-PID outbound PowerShell TCP/443 payload packets of >=1200 bytes to content.dropboxapi.com SNI in 30s; no decrypted upload, account identity, file or exfiltration established.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] {
                "Coherent typed IPv4 packet predicate, unique identifiers and rule-owned bounded UTC observation.",
                "Only locally observed process or transport fields; no remote security outcome asserted."
            },
            NegativeConditions = new[] {
                "Missing/contradictory typed fields, duplicate IDs, reverse UTC time and stale state fail closed.",
                "No terminal login, decrypted content, file write, interface proof, authorization or actor inferred."
            },
            FalsePositives = new[] {
                "Administration, diagnostics, updates, sensor attribution errors and authorized security tests may share the observable pattern."
            },
            MinimumConfidence = 80, WindowThreshold = 5,
            Window = TimeSpan.FromSeconds(30), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "powershell_cloud_tls_payload_burst",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] {
                "source-specific positive/benign cases", "missing and contradictory evidence",
                "duplicate, reverse and expiry", "cooldown recovery", "raw Info excluded",
                "neighboring rule non-convergence", "Candidate Shadow registration"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research736CountWindow _burst = new();
        public R852_PowershellCloudTlsPayloadBurstRule() : base(Rule, Profile) { }
        

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || !Research676Evidence.Process(r, "powershell.exe", "powershell")
                || r.DestinationPort != 443 || r.L4Len is not int payloadLength || payloadLength is < 1200 or > 8192
                || string.IsNullOrWhiteSpace(r.TlsVersion)
                || !string.Equals(r.Sni, "content.dropboxapi.com", StringComparison.OrdinalIgnoreCase)
                || r.HttpMethod != null || r.HttpUri != null || r.DnsQname != null
                || r.DnsIsResponse || string.Equals(r.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)) return NoMatch();
            var key = r.Source! + "|" + r.Destination! + "|" + r.ProcessId + "|" + r.DestinationPort;
            if (!_burst.Observe(key, r.Id, payloadLength, context.TimestampUtc, 5, 30, 10000)) return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[] {
                new DetectionEvidenceItem("research.identifier", "workbook.R1204", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "powershell_cloud_tls_payload_burst", "rule"),
                new DetectionEvidenceItem("outcome", "typed_observation_only_attribution_and_security_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "PowerShell Dropbox-content TLS payload burst observed; process provenance, authorization, causality and outcome unknown.",
                evidence, confidence => {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_signal");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 5, windowSeconds: 30);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

