// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, 0 tests executed; workbook.R1011.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R798_DnsThenRecurringTlsSniRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R798",
            Name: "DNS A query followed by same-process repeating TLS/SNI cadence",
            Category: "EvasionTunnel",
            Description: "DNS A query followed by same-process repeating TLS/SNI cadence. Packet/process shape only; no authorization, exploitation, transfer completion, command execution or compromise inferred.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R798.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R798",
            Name = "DNS A query followed by same-process repeating TLS/SNI cadence",
            Category = "EvasionTunnel",
            Description = "workbook.R1011: admitted only an independent bounded packet/process evidence shape; the source analytic requires endpoint, audit, allowlist or outcome telemetry not presently established.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Dns, RuleTelemetryKind.Tls, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "dns.qname", "tls.sni", "process.id", "l4.length" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Coherent typed fields, strict directionality, unique packet IDs and this rule's own network predicate.", "Instance-owned bounded monotonic UTC correlation state; source-only, no live reachability claimed." },
            NegativeConditions = new[] { "Missing or contradictory transport/process, duplicate IDs, reversed/expired time and cooldown repeats fail closed.", "No free-form Info assertions, credentials, raw payload, endpoint event, authorization, C2 or impact claims." },
            FalsePositives = new[] { "Authorized maintenance, software deployment, operations, inventory, troubleshooting, and field engineering may generate these shapes." },
            MinimumConfidence = 80,
            WindowThreshold = 4,
            Window = TimeSpan.FromSeconds(120),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "R798_cadence_distinct_provenance",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive/benign", "contradictory/missing telemetry", "duplicate/reverse-time/expiry", "cooldown recovery", "privacy", "Candidate Shadow", "independence/registry uniqueness" }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research796DnsThenTlsCadenceWindow _cadence = new();

        public R798_DnsThenRecurringTlsSniRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            if (Research786NetworkEvidence.PrivatePublic(r) && Research786NetworkEvidence.DnsQuestion(r)
                && r.IsUdp && Research676Evidence.Process(r, "powershell.exe")
                && string.Equals(r.DnsQtype, "A", StringComparison.OrdinalIgnoreCase))
            {
                var firstKey = r.Source + "|" + r.ProcessId + "|" + r.DnsQname!.ToLowerInvariant();
                _cadence.Observe(firstKey, r.Id, context.TimestampUtc, true, 0);
                return NoMatch();
            }
            if (!Research786NetworkEvidence.PrivatePublic(r)
                || !Research786NetworkEvidence.TcpData(r)
                || !Research676Evidence.Process(r, "powershell.exe")
                || r.DestinationPort != 443
                || string.IsNullOrWhiteSpace(r.TlsVersion) || string.IsNullOrWhiteSpace(r.Sni)
                || r.HttpMethod != null || r.DnsQname != null || r.L4Len is not int payloadLength || payloadLength is < 128 or > 512)
                return NoMatch();
            var key = r.Source + "|" + r.ProcessId + "|" + r.Sni!.ToLowerInvariant();
            if (!_cadence.Observe(key, r.Id, context.TimestampUtc, false, payloadLength)) return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1011", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "r798_cadence_typed_network_observation", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_authorization_causality_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "DNS A query followed by same-process repeating TLS/SNI cadence observed; asset role, causal context and outcome unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "typed-packet-or-local-process-evidence");
                    confidence.AddEvidence(0.33, "independent-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-monotonic-correlation");
                },
                count: 4, windowSeconds: 120);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
