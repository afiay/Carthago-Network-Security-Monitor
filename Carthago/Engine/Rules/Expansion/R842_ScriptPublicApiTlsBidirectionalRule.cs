// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; 0 tests/builds executed. workbook.R2028.
using System;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R842_ScriptPublicApiTlsBidirectionalRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R842", Name: "Script-attributed public API TLS then reverse-tuple payload", Category: "CommandControl",
            Description: "PowerShell or wscript TLS request to a selected web-service SNI then reverse-5-tuple TCP reply within 60 seconds; no decrypted C2 content or commands inferred.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R842.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R842", Name = "Script-attributed public API TLS then reverse-tuple payload", Category = "CommandControl",
            Description = "workbook.R2028: PowerShell or wscript TLS request to a selected web-service SNI then reverse-5-tuple TCP reply within 60 seconds; no decrypted C2 content or commands inferred.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] {
                "Typed IPv4 packet predicate and independent UTC-bounded observation match.",
                "No unobserved endpoint execution, authentication or causality asserted."
            },
            NegativeConditions = new[] {
                "Missing or contradictory typed fields, repeated IDs, reverse UTC order and stale state fail closed.",
                "No encrypted contents interpreted; no benign authorization inferred."
            },
            FalsePositives = new[] {
                "Authorized automation, infrastructure updates, diagnostics and red-team traffic can share the observable shape."
            },
            MinimumConfidence = 80, WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(60), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "script_public_api_tls_reverse_tuple_payload",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] {
                "specific positive/benign case", "missing/contradictory evidence",
                "duplicate and expired observation", "cooldown recovery", "raw Info excluded",
                "non-convergence", "Candidate Shadow registration"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R842_ScriptPublicApiTlsBidirectionalRule() : base(Rule, Profile) { }

        private static bool ValidTls(TrafficRecord record) =>
            Research786NetworkEvidence.TcpData(record)
            && !string.IsNullOrWhiteSpace(record.TlsVersion) && !string.IsNullOrWhiteSpace(record.Sni)
            && record.HttpMethod == null && record.HttpUri == null && record.DnsQname == null
            && !record.DnsIsResponse
            && !string.Equals(record.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(record.ApplicationProtocol, "DNS", StringComparison.OrdinalIgnoreCase);

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (ValidTls(r) && Research786NetworkEvidence.PrivatePublic(r)
                && r.DestinationPort == 443 && Research676Evidence.Process(r, "powershell.exe", "powershell", "wscript.exe", "wscript")
                && (string.Equals(r.Sni, "api.github.com", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(r.Sni, "discord.com", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(r.Sni, "pastebin.com", StringComparison.OrdinalIgnoreCase)))
            {
                _stages.Observe(r.Source! + "|" + r.Destination! + "|" + r.SourcePort, r.Id, context.TimestampUtc, true, 60);
                return NoMatch();
            }
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PublicPrivate(r)
                || r.SourcePort != 443 || r.DestinationPort is < 1024 or > 65535
                || r.L4Len is < 300 or > 4096 || r.HttpMethod != null || r.DnsQname != null
                || string.Equals(r.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                || !_stages.Observe(r.Destination! + "|" + r.Source! + "|" + r.DestinationPort, r.Id, context.TimestampUtc, false, 60)) return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[] {
                new DetectionEvidenceItem("research.identifier", "workbook.R2028", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "script_public_api_tls_reverse_tuple_payload", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_observation_only_causality_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Script-attributed public API TLS then reverse-tuple payload observed; provenance, authorization and outcome unverified.",
                evidence, confidence => {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "source_specific_independent_observable_predicate");
                    confidence.AddCorrelation(0.12, "bounded_utc_correlation");
                }, count: 2, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

