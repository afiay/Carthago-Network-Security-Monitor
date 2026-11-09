// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 tests executed; workbook.R1016.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R799_DnsTxtThenSameHostHttpPostRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R799",
            Name: "process-linked DNS TXT query then cleartext HTTP POST to same host",
            Category: "EvasionTunnel",
            Description: "process-linked DNS TXT query then cleartext HTTP POST to same host. Packet/process shape only; no authorization, exploitation, transfer completion, command execution or compromise inferred.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R799.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R799",
            Name = "process-linked DNS TXT query then cleartext HTTP POST to same host",
            Category = "EvasionTunnel",
            Description = "workbook.R1016: admitted only an independent bounded packet/process evidence shape; the source analytic requires endpoint, audit, allowlist or outcome telemetry not presently established.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Dns, RuleTelemetryKind.Http, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "dns.qname", "http.host", "http.method", "process.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Coherent typed fields, strict directionality, unique packet IDs and this rule's own network predicate.", "Instance-owned bounded monotonic UTC correlation state; source-only, no live reachability claimed." },
            NegativeConditions = new[] { "Missing or contradictory transport/process, duplicate IDs, reversed/expired time and cooldown repeats fail closed.", "No free-form Info assertions, credentials, raw payload, endpoint event, authorization, C2 or impact claims." },
            FalsePositives = new[] { "Authorized maintenance, software deployment, operations, inventory, troubleshooting, and field engineering may generate these shapes." },
            MinimumConfidence = 80,
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "R799_seq_distinct_provenance",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive/benign", "contradictory/missing telemetry", "duplicate/reverse-time/expiry", "cooldown recovery", "privacy", "Candidate Shadow", "independence/registry uniqueness" }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _sequence = new();

        public R799_DnsTxtThenSameHostHttpPostRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            if (Research786NetworkEvidence.PrivatePublic(r) && Research786NetworkEvidence.DnsQuestion(r)
                && r.IsUdp && Research676Evidence.Process(r, "curl", "curl.exe")
                && string.Equals(r.DnsQtype, "TXT", StringComparison.OrdinalIgnoreCase))
            {
                _sequence.Observe(r.Source + "|" + r.ProcessId + "|" + r.DnsQname!.ToLowerInvariant(),
                    r.Id, context.TimestampUtc, true, 45);
                return NoMatch();
            }
            if (!Research786NetworkEvidence.PrivatePublic(r) || !Research786NetworkEvidence.TcpData(r)
                || !Research676Evidence.Process(r, "curl", "curl.exe")
                || r.DestinationPort != 80
                || !WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                || method != "POST" || !uri.StartsWith("/api/", StringComparison.OrdinalIgnoreCase)
                || string.IsNullOrWhiteSpace(r.HttpHost)
                || !_sequence.Observe(r.Source + "|" + r.ProcessId + "|" + r.HttpHost!.ToLowerInvariant(),
                    r.Id, context.TimestampUtc, false, 45)) return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1016", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "r799_seq_typed_network_observation", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_authorization_causality_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "process-linked DNS TXT query then cleartext HTTP POST to same host observed; asset role, causal context and outcome unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "typed-packet-or-local-process-evidence");
                    confidence.AddEvidence(0.33, "independent-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-monotonic-correlation");
                },
                count: 2, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
