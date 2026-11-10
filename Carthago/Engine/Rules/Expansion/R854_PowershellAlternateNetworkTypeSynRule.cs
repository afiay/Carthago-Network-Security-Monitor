// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; no tests or builds executed. workbook.R1333.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R854_PowershellAlternateNetworkTypeSynRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R854", Name: "PowerShell public SYNs tagged Wi-Fi and Cellular", Category: "Exfiltration",
            Description: "Same local PowerShell PID has typed public TCP/8443 SYNs tagged Wi-Fi and Cellular within 90s; labels are untrusted enrichment, not physical interface or exfiltration proof.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R854.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R854", Name = "PowerShell public SYNs tagged Wi-Fi and Cellular", Category = "Exfiltration",
            Description = "workbook.R1333: Same local PowerShell PID has typed public TCP/8443 SYNs tagged Wi-Fi and Cellular within 90s; labels are untrusted enrichment, not physical interface or exfiltration proof.",
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
            MinimumConfidence = 80, WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(90), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "powershell_wifi_cellular_public_syn",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] {
                "source-specific positive/benign cases", "missing and contradictory evidence",
                "duplicate, reverse and expiry", "cooldown recovery", "raw Info excluded",
                "neighboring rule non-convergence", "Candidate Shadow registration"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research706DistinctWindow _types = new();
        public R854_PowershellAlternateNetworkTypeSynRule() : base(Rule, Profile) { }
        

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r) || !Research676Evidence.Syn(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || r.DestinationPort != 8443 || !Research676Evidence.Process(r, "powershell.exe", "powershell")
                || !(string.Equals(r.NetworkType, "Wi-Fi", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(r.NetworkType, "Cellular", StringComparison.OrdinalIgnoreCase))) return NoMatch();
            var key = r.Source! + "|" + r.ProcessId;
            if (!_types.Observe(key, r.NetworkType!.ToLowerInvariant(), r.Id, context.TimestampUtc, 2, 90)) return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[] {
                new DetectionEvidenceItem("research.identifier", "workbook.R1333", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "powershell_wifi_cellular_public_syn", "rule"),
                new DetectionEvidenceItem("outcome", "typed_observation_only_attribution_and_security_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "PowerShell public SYNs tagged Wi-Fi and Cellular observed; process provenance, authorization, causality and outcome unknown.",
                evidence, confidence => {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_signal");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 2, windowSeconds: 90);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

