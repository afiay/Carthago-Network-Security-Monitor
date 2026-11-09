// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; authored xUnit source, zero tests executed. workbook.R1304.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R777_WindowsGitRepositoryHttpPostBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R777",
            Name: "Windows git HTTP POST burst to code-repository host",
            Category: "EvasionTunnel",
            Description: "Windows git HTTP POST burst to code-repository host. This is a narrow packet/process association, not proof of file access, transfer completion, command execution, exfiltration, or compromise.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R777.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R777",
            Name = "Windows git HTTP POST burst to code-repository host",
            Category = "EvasionTunnel",
            Description = "workbook.R1304: narrowed to typed local process enrichment and observed network shape; original endpoint, data-access and outcome claims are not observable.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "process.name", "process.id", "destination.port", "l4.length" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Typed coherent packet fields, local process attribution, unique packet IDs and bounded UTC time window." },
            NegativeConditions = new[] { "Reject contradictory transport, missing process, duplicate IDs, reversed timestamps, expired windows and cooldown repeats.", "No file reads, credentials, command lines, authenticated identity, transfer completion, C2, impact or compromise inferred." },
            FalsePositives = new[] { "Authorized administration, backup, software deployment and automated integration can produce similar network traffic." },
            MinimumConfidence = 80,
            WindowThreshold = 5,
            Window = TimeSpan.FromSeconds(20),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "R777_process_peer_port_independent_window",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive and benign near miss", "missing/contradictory telemetry", "duplicate ID, reverse-time and expiry", "cooldown recovery", "privacy and non-convergence", "Candidate Shadow and registry uniqueness" }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research736CountWindow _window = new();

        public R777_WindowsGitRepositoryHttpPostBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (r == null || r.Id == Guid.Empty
                || !Research676Evidence.PrivateToPublic(r)
                || !Research676Evidence.Process(r, "git.exe")
                || !Research676Evidence.Tcp(r)
                || r.TcpFlags != 0x18
                || !(WebSignatureRequestEvidence.TryGet(r, out var method, out _)
                && method == "POST" && r.DestinationPort == 80
                && Research656Evidence.HostIs(r.HttpHost, "github.com")
                && r.TlsVersion == null && r.DnsQname == null
                && r.L4Len is >= 80 and <= 4096))
                return NoMatch();

            var key = r.Source + "|" + r.Destination + "|" + r.DestinationPort + "|" + r.ProcessId;
            if (!_window.Observe(key, r.Id, r.L4Len!.Value, context.TimestampUtc,
                    5, 20))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1304", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "r777_typed_process_network_burst", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_transfer_and_endpoint_outcomes_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Windows git HTTP POST burst to code-repository host observed; endpoint intent, data access and transfer outcome unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "independent-source-predicate");
                    confidence.AddCorrelation(0.12, "bounded-instance-correlation");
                },
                count: 5, windowSeconds: 20);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
