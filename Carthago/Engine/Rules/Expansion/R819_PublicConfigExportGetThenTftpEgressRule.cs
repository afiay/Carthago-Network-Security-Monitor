// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit source authored first, 0 tests executed; workbook.R1676.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R819_PublicConfigExportGetThenTftpEgressRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R819",
            Name: "public config-export API GET then private host public TFTP-port UDP egress",
            Category: "NetworkDiscovery",
            Description: "public config-export API GET then private host public TFTP-port UDP egress. Source-only network/process evidence; no authorization, compromise or successful outcome inferred.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R819.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R819",
            Name = "public config-export API GET then private host public TFTP-port UDP egress",
            Category = "NetworkDiscovery",
            Description = "workbook.R1676: A URL path and TFTP-port datagram do not prove configuration contents, authentication, SNMP behavior or successful export.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "packet.id", "destination.port", "http.uri" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Strict typed transport, coherent direction, unique packet IDs and the independent source predicate.",
                "Bounded instance-owned UTC correlation state; no live producer or replay quality claimed."
            },
            NegativeConditions = new[]
            {
                "Missing or contradictory fields, duplicate IDs, reverse-time events and expired evidence fail closed.",
                "No inferred local file, identity, configuration, credential, success or compromise event."
            },
            FalsePositives = new[]
            {
                "Authorized administration, CI/CD, diagnostics, inventory and software upgrades may show these network patterns."
            },
            MinimumConfidence = 80,
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(90),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "R819_public_config_export_get_then_tftp_port_egress",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] {
                "positive/benign", "missing/contradictory fields", "replay/reverse/expiry",
                "cooldown", "evidence privacy", "Candidate Shadow", "independent registry identity"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _sequence = new();

        public R819_PublicConfigExportGetThenTftpEgressRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            if (Research786NetworkEvidence.TcpData(r) && Research786NetworkEvidence.PublicPrivate(r)
                && r.DestinationPort == 80
                && WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                && method == "GET" && uri == "/api/config/export")
            {
                _sequence.Observe(r.Destination!, r.Id, context.TimestampUtc, true, 90);
                return NoMatch();
            }
            if (!Research786NetworkEvidence.UdpData(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || r.DestinationPort != 69 || r.L4Len is < 64 or > 1024
                || r.HttpMethod != null || r.DnsQname != null
                || !_sequence.Observe(r.Source!, r.Id, context.TimestampUtc, false, 90))
                return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1676", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "r819_public_config_export_get_then_tftp_port_egress", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_causality_authorization_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "public config-export API GET then private host public TFTP-port UDP egress observed; source attribution, authorization and outcome unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "typed_packet_or_process_fields");
                    confidence.AddEvidence(0.33, "independent_workbook_source_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_correlation");
                },
                count: 2, windowSeconds: 90);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
