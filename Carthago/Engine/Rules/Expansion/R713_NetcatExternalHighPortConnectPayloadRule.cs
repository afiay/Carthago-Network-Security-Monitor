// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R2306.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R713_NetcatExternalHighPortConnectPayloadRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R713",
            Name: "Netcat process external high-port SYN followed by raw TCP payload",
            Category: "EvasionTunnel",
            Description: "The same best-effort Netcat/Ncat PID sends an outbound SYN to a public uncommon high port and then a raw TCP payload observation on the same tuple within 30 seconds. Command-line -e/-c flags, shell execution, server acceptance, and reverse-shell semantics are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R713.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R713",
            Name = "Netcat process external high-port SYN followed by raw TCP payload",
            Category = "EvasionTunnel",
            Description = "Workbook R2306: the Sigma source rule is command-line based. Carthago has no command line, so this candidate deliberately requires Netcat process attribution plus an ordered external connect-and-payload shape and never labels the event a confirmed reverse shell.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "tcp.flags_or_payload", "process.name", "process.id", "destination.port" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed producer fields and this rule's independent exact predicate.",
                "Bounded correlation uses unique packet IDs and UTC ordering where multiple observations are required.",
                "Only the observable packet, flow, parser, or best-effort process association is claimed."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory protocol fields, wrong network direction, and Info-only indicators.",
                "Reject packet-ID replay, out-of-order state, stale windows, and cooldown repeats.",
                "Do not infer authentication, exploit success, file writes, command lines, transfer completion, or compromise."
            },
            FalsePositives = new[] { "Legitimate Netcat/Ncat diagnostics, ad-hoc data transfer, service testing, and security validation can use public high ports." },
            MinimumConfidence = 82,
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(30),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "local_host+netcat_pid+external_tuple",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive real-life-shaped case and benign near miss",
                "wrong or missing telemetry and contradictory protocol fields",
                "duplicate packet ID and out-of-order timestamp where relevant",
                "window expiry and cooldown behavior",
                "privacy/redaction, registry uniqueness, Candidate Shadow, and non-convergence"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research676TcpSynPair _pair = new();

        public R713_NetcatExternalHighPortConnectPayloadRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research706Evidence.Netcat(r)) return NoMatch();
            var outbound = Research706Evidence.PrivateToPublic(r);
            if (!outbound) return NoMatch();
            var uncommon = r.DestinationPort is > 1024 and <= 65535
                && r.DestinationPort is not (1883 or 3306 or 3389 or 4443 or 5432 or 6379 or 8080 or 8443 or 11211);
            if (!uncommon) return NoMatch();
            var first = Research706Evidence.TcpSyn(r);
            var second = Research706Evidence.TcpPayload(r);
            if (!first && !second) return NoMatch();
            var process = NetworkBatch266270Evidence.Process(r);
            var key = r.Source + "|" + r.Destination + "|" + r.SourcePort + "|" + r.DestinationPort + "|" + r.ProcessId + "|" + process;
            if (!_pair.Observe(key, r.Id, context.TimestampUtc, first))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2306", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "netcat_external_high_port_syn_then_payload", "rule"),
                new DetectionEvidenceItem("outcome", "netcat_connect_payload_shape_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Netcat/Ncat external high-port connect followed by raw TCP payload observed; shell execution and reverse-shell semantics are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 2,
                windowSeconds: 30);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
