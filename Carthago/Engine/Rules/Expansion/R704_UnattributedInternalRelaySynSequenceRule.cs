// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R1793.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R704_UnattributedInternalRelaySynSequenceRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R704", Name: "Unattributed private host receives internal high-port SYN then initiates admin-service SYN to another private host", Category: "EvasionTunnel",
            Description: "Unattributed private host receives internal high-port SYN then initiates admin-service SYN to another private host. Two SYN packets do not prove a proxy, C2 relay, ESXi shell tool, accepted connection or forwarded payload.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R704.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R704", Name = "Unattributed private host receives internal high-port SYN then initiates admin-service SYN to another private host", Category = "EvasionTunnel",
            Description = "Workbook R1793: R680 requires an unusual attributed process fanout; this rule explicitly requires missing process attribution and an ordered relay-shaped pair. Two SYN packets do not prove a proxy, C2 relay, ESXi shell tool, accepted connection or forwarded payload.",
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
            FalsePositives = new[] { "Two SYN packets do not prove a proxy, C2 relay, ESXi shell tool, accepted connection or forwarded payload. Authorized software distribution, administration and security testing may resemble this signal." },
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

        public R704_UnattributedInternalRelaySynSequenceRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research676Evidence.Syn(r)
            || r.ProcessId != 0 || !string.IsNullOrWhiteSpace(r.ProcessName)
            || !Research676Evidence.PrivatePair(r, out var src, out var dst))
            return NoMatch();

        var second = r.DestinationPort is 22 or 445 or 3389 or 5985 or 5986 or 3306 or 5432 or 6379;
        var first = r.DestinationPort is > 1024 and <= 65535 && !second;
        if (!first && !second) return NoMatch();

        var relay = first ? r.Destination! : r.Source!;
        var peer = first ? r.Source! : r.Destination!;
        if (!_relay.Observe("internal|"+relay, peer, r.Id, context.TimestampUtc, first))
            return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1793", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "independent_internalrelay_shape", "rule"),
                new DetectionEvidenceItem("outcome", "internal_syn_relay_shape_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(context, SeverityLevel.Low,
                "Unattributed private host receives internal high-port SYN then initiates admin-service SYN to another private host observed; Two SYN packets do not prove a proxy, C2 relay, ESXi shell tool, accepted connection or forwarded payload.",
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
