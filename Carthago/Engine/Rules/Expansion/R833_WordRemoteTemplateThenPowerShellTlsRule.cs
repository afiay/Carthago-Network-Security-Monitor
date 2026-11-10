// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; 0 tests executed. workbook.R1970.
using System;
using System.Linq;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R833_WordRemoteTemplateThenPowerShellTlsRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R833", Name: "Word remote template GET followed by PowerShell other-peer TLS", Category: "Execution",
            Description: "Same local IP Word template HTTP request and later PowerShell public TLS egress; no parent process lineage or malicious document is observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R833.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R833", Name = "Word remote template GET followed by PowerShell other-peer TLS", Category = "Execution",
            Description = "workbook.R1970: Same local IP Word template HTTP request and later PowerShell public TLS egress; no parent process lineage or malicious document is observed.",
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
            MinimumConfidence = 80, WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "word_template_get_then_powershell_tls",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "specific positive/benign case", "missing/contradictory evidence", "duplicate/reverse/expiry",
                "cooldown recovery", "raw Info excluded", "non-convergence", "Candidate Shadow registration"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research806DifferentPeerWindow _peers = new();
        public R833_WordRemoteTemplateThenPowerShellTlsRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r))
                return NoMatch();
            if (r.DestinationPort == 80 && Research676Evidence.Process(r, "winword.exe")
                && WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                && method == "GET"
                && (uri.EndsWith(".dotm", StringComparison.OrdinalIgnoreCase)
                    || uri.EndsWith(".dotx", StringComparison.OrdinalIgnoreCase))
                && !string.IsNullOrWhiteSpace(r.HttpHost))
            {
                _peers.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc, true);
                return NoMatch();
            }
            if (r.DestinationPort != 8443 || !Research676Evidence.Process(r, "powershell.exe", "pwsh.exe")
                || r.L4Len is < 256 or > 4096 || string.IsNullOrWhiteSpace(r.TlsVersion)
                || string.IsNullOrWhiteSpace(r.Sni) || r.HttpMethod != null || r.HttpUri != null
                || r.DnsQname != null || r.DnsIsResponse
                || string.Equals(r.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                || !_peers.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc, false))
                return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1970", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "word_template_get_then_powershell_tls", "rule"),
                new DetectionEvidenceItem("outcome", "typed_network_observation_only_causality_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Word remote template GET followed by PowerShell other-peer TLS observed; authorization, provenance and outcomes unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "typed_packet_and_optional_local_process_fields");
                    confidence.AddEvidence(0.33, "independent_workbook_derived_narrow_predicate");
                    confidence.AddCorrelation(0.12, "coherent_endpoints_and_bounded_time");
                }, count: 2, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
        
    }
}

