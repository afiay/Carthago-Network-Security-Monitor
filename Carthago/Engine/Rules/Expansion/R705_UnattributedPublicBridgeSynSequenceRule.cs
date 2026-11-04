// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R1783.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R705_UnattributedPublicBridgeSynSequenceRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R705", Name: "Unattributed private host receives public high-port SYN then initiates SYN to a different public peer", Category: "EvasionTunnel",
            Description: "Unattributed private host receives public high-port SYN then initiates SYN to a different public peer. Host-level SYN correlation does not establish netcat/socat, reverse tunnel, traffic bridging or successful connections.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R705.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R705", Name = "Unattributed private host receives public high-port SYN then initiates SYN to a different public peer", Category = "EvasionTunnel",
            Description = "Workbook R1783: R674 requires the same attributed process; this candidate explicitly requires no PID/name and correlates at host level only. Host-level SYN correlation does not establish netcat/socat, reverse tunnel, traffic bridging or successful connections.",
            Severity = SeverityLevel.Low,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source","destination","tcp.flags","source.port","destination.port" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require typed packet/process fields and this rule's exact independent predicate.",
                "Where process identity is required it is best-effort local tuple enrichment, not an authenticated endpoint event.",
                "Where a sequence is required, only bounded unique packet IDs from one relay/peer context can satisfy it."
            },
            NegativeConditions = new[]
            {
                "Reject missing producer fields, wrong method/transport/direction and free-form Info-only indicators.",
                "Reject duplicates, out-of-order timestamps, expired sequences and cooldown repeats.",
                "Do not infer transfer completion, credentials, C2, proxy forwarding, CVE exploitation or device compromise."
            },
            FalsePositives = new[] { "Host-level SYN correlation does not establish netcat/socat, reverse tunnel, traffic bridging or successful connections. Authorized software distribution, administration and security testing may resemble this signal." },
            MinimumConfidence = 78,
            WindowThreshold = 2,
            Window = TimeSpan.FromMinutes(5),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "independent_rule_specific_process_peer_or_sequence",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "exact positive and benign near miss", "wrong process/method/protocol or network direction",
                "missing process attribution or explicit no-process gate where required",
                "duplicate/out-of-order/expiry and cooldown", "Candidate Shadow and registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research696RelayWindow _relay = new();

        public R705_UnattributedPublicBridgeSynSequenceRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research676Evidence.Syn(r)
            || r.ProcessId != 0 || !string.IsNullOrWhiteSpace(r.ProcessName))
            return NoMatch();

        var inbound = Research676Evidence.PublicToPrivate(r)
            && r.DestinationPort is > 1024 and <= 65535
            && r.DestinationPort is not (3389 or 445 or 5985 or 5986 or 5900);
        var outbound = Research676Evidence.PrivateToPublic(r)
            && r.DestinationPort is 22 or 443 or 1080 or 3128 or 8080 or 8443 or 8888;
        if (!inbound && !outbound) return NoMatch();

        var relay = inbound ? r.Destination! : r.Source!;
        var peer = inbound ? r.Source! : r.Destination!;
        if (!_relay.Observe("external|"+relay, peer, r.Id, context.TimestampUtc, inbound))
            return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1783", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "independent_externalrelay_shape", "rule"),
                new DetectionEvidenceItem("outcome", "public_bridge_syn_shape_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(context, SeverityLevel.Low,
                "Unattributed private host receives public high-port SYN then initiates SYN to a different public peer observed; Host-level SYN correlation does not establish netcat/socat, reverse tunnel, traffic bridging or successful connections.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "coherent-source-destination-or-sequence");
                }, count: 2, windowSeconds: 300);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
