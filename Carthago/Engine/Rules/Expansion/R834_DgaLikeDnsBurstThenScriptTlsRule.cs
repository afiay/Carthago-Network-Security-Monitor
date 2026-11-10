// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; 0 tests executed. workbook.R2000.
using System;
using System.Linq;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R834_DgaLikeDnsBurstThenScriptTlsRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R834", Name: "script-host distinct DGA-like DNS burst followed by TLS payload", Category: "DnsAdvanced",
            Description: "Four script-attributed high-digit DNS questions and a subsequent TLS payload at a public peer; no DGA attribution, NXDOMAIN ratio or malicious verdict is established.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R834.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R834", Name = "script-host distinct DGA-like DNS burst followed by TLS payload", Category = "DnsAdvanced",
            Description = "workbook.R2000: Four script-attributed high-digit DNS questions and a subsequent TLS payload at a public peer; no DGA attribution, NXDOMAIN ratio or malicious verdict is established.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Coherent typed IPv4 packets, exact source-specific predicate and bounded UTC correlation where used.",
                "Packet ID/protocol/process association is observation-only; no authenticated endpoint action asserted."
            },
            NegativeConditions = new[]
            {
                "Missing/contradictory fields, duplicate packet IDs, reversed UTC order and stale state fail closed.",
                "Do not infer completed transfers, successful access, exploit execution, credentials or actor identity."
            },
            FalsePositives = new[]
            {
                "Authorized updates, administrative troubleshooting, diagnostics, scans and red-team activity can match; apply asset/process allowlists before promotion."
            },
            MinimumConfidence = 80, WindowThreshold = 5,
            Window = TimeSpan.FromSeconds(90),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "script_dga_like_dns_burst_then_tls",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "specific positive/benign case", "missing/contradictory evidence", "duplicate/reverse/expiry",
                "cooldown recovery", "raw Info excluded", "non-convergence", "Candidate Shadow registration"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research706DistinctWindow _distinct = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R834_DgaLikeDnsBurstThenScriptTlsRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.PrivatePublic(r)
                || !Research676Evidence.Process(r, "wscript.exe", "cscript.exe"))
                return NoMatch();
            var key = r.Source! + "|" + r.ProcessId;
            if (Research786NetworkEvidence.DnsQuestion(r) && r.DestinationPort == 53
                && string.Equals(r.DnsQtype, "A", StringComparison.OrdinalIgnoreCase)
                && HasMixedLongLabel(r.DnsQname))
            {
                if (_distinct.Observe(key, r.DnsQname!.ToLowerInvariant(), r.Id,
                    context.TimestampUtc, 4, 50))
                    _stages.Observe(key, r.Id, context.TimestampUtc, true, 90);
                return NoMatch();
            }
            if (!Research786NetworkEvidence.TcpData(r) || r.DestinationPort != 8443
                || r.L4Len is < 256 or > 4096 || string.IsNullOrWhiteSpace(r.TlsVersion)
                || string.IsNullOrWhiteSpace(r.Sni) || r.HttpMethod != null || r.HttpUri != null
                || r.DnsQname != null || r.DnsIsResponse
                || string.Equals(r.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                || !_stages.Observe(key, r.Id, context.TimestampUtc, false, 90))
                return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2000", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "script_dga_like_dns_burst_then_tls", "rule"),
                new DetectionEvidenceItem("outcome", "typed_network_observation_only_causality_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "script-host distinct DGA-like DNS burst followed by TLS payload observed; authorization, provenance and outcomes unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "typed_packet_and_optional_local_process_fields");
                    confidence.AddEvidence(0.33, "independent_workbook_derived_narrow_predicate");
                    confidence.AddCorrelation(0.12, "coherent_endpoints_and_bounded_time");
                }, count: 5, windowSeconds: 90);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
        private static bool HasMixedLongLabel(string? name)
        {
            if (string.IsNullOrWhiteSpace(name) || name.Length > 253
                || !name.Contains('.')) return false;
            var label = name.Split('.')[0];
            return label.Length is >= 18 and <= 63
                && label.Count(char.IsDigit) >= 7
                && label.Count(char.IsLetter) >= 7
                && label.All(c => char.IsAsciiLetterOrDigit(c));
        }
    }
}

