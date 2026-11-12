// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; no tests or builds executed. workbook.R1222.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R855_HostdExternalHttpPostBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R855", Name: "Hostd-attributed public HTTP/8080 POST burst", Category: "Exfiltration",
            Description: "Five hostd/vpxa-attributed cleartext POST packets to one public TCP/8080 peer in 20s; no ESXi provenance, FTP, transferred file, unauthorized policy or completed exfiltration established.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R855.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R855", Name = "Hostd-attributed public HTTP/8080 POST burst", Category = "Exfiltration",
            Description = "workbook.R1222: Five hostd/vpxa-attributed cleartext POST packets to one public TCP/8080 peer in 20s; no ESXi provenance, FTP, transferred file, unauthorized policy or completed exfiltration established.",
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
            Window = TimeSpan.FromSeconds(20), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "hostd_public_8080_http_post_burst",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] {
                "source-specific positive/benign cases", "missing and contradictory evidence",
                "duplicate, reverse and expiry", "cooldown recovery", "raw Info excluded",
                "neighboring rule non-convergence", "Candidate Shadow registration"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research736CountWindow _posts = new();
        public R855_HostdExternalHttpPostBurstRule() : base(Rule, Profile) { }
        

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || r.DestinationPort != 8080 || !Research676Evidence.Process(r, "hostd", "hostd.exe", "vpxa")
                || r.L4Len is not int payloadLength || payloadLength is < 1000 or > 4096
                || !WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                || method != "POST" || !uri.StartsWith("/api/", StringComparison.OrdinalIgnoreCase)) return NoMatch();
            var key = r.Source! + "|" + r.Destination! + "|" + r.ProcessId + "|" + uri;
            if (!_posts.Observe(key, r.Id, payloadLength, context.TimestampUtc, 5, 20, 5000)) return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[] {
                new DetectionEvidenceItem("research.identifier", "workbook.R1222", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "hostd_public_8080_http_post_burst", "rule"),
                new DetectionEvidenceItem("outcome", "typed_observation_only_attribution_and_security_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Hostd-attributed public HTTP/8080 POST burst observed; process provenance, authorization, causality and outcome unknown.",
                evidence, confidence => {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_signal");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 5, windowSeconds: 20);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

