// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; 0 tests executed. workbook.R3076.
using System;
using System.Linq;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R830_DirectIpDistinctExecutableGetRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R830", Name: "two distinct executable GET paths at one public IP host", Category: "HttpApi",
            Description: "Distinct cleartext executable requests to one public direct-IP HTTP origin are observed; no Zone.Identifier stream, downloaded file or execution is proven.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R830.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R830", Name = "two distinct executable GET paths at one public IP host", Category = "HttpApi",
            Description = "workbook.R3076: Distinct cleartext executable requests to one public direct-IP HTTP origin are observed; no Zone.Identifier stream, downloaded file or execution is proven.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http },
            RequiredFields = new[] { "source", "destination", "packet.id", "http.uri", "http.host" },
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
            Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "direct_ip_distinct_executable_get",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "specific positive/benign case", "missing/contradictory evidence", "duplicate/reverse/expiry",
                "cooldown recovery", "raw Info excluded", "non-convergence", "Candidate Shadow registration"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research706DistinctWindow _distinct = new();
        public R830_DirectIpDistinctExecutableGetRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || r.DestinationPort != 80
                || !WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                || method != "GET" || !DirectIpHost(r)
                || !(uri.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                    || uri.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                    || uri.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase))
                || !_distinct.Observe(r.Source! + "|" + r.Destination!,
                    uri.ToLowerInvariant(), r.Id, context.TimestampUtc, 2, 45))
                return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R3076", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "direct_ip_distinct_executable_get", "rule"),
                new DetectionEvidenceItem("outcome", "typed_network_observation_only_causality_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "two distinct executable GET paths at one public IP host observed; authorization, provenance and outcomes unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "typed_packet_and_optional_local_process_fields");
                    confidence.AddEvidence(0.33, "independent_workbook_derived_narrow_predicate");
                    confidence.AddCorrelation(0.12, "coherent_endpoints_and_bounded_time");
                }, count: 2, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
        private static bool DirectIpHost(TrafficRecord r)
            => !string.IsNullOrWhiteSpace(r.HttpHost)
                && System.Net.IPAddress.TryParse(r.HttpHost, out var host)
                && host.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                && string.Equals(host.ToString(), r.Destination, StringComparison.Ordinal);
    }
}

