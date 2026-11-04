// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R2043.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R703_ScriptProcessRepeatedPublicUdpPayloadBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R703", Name: "Script-like process emits repeated raw UDP payloads to one public high-port peer", Category: "EvasionTunnel",
            Description: "Script-like process emits repeated raw UDP payloads to one public high-port peer. Five UDP datagrams do not prove non-application C2, exfiltration, payload semantics or server receipt.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R703.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R703", Name = "Script-like process emits repeated raw UDP payloads to one public high-port peer", Category = "EvasionTunnel",
            Description = "Workbook R2043: R670 handles timed ICMP; existing process-egress rules are TCP-oriented. This rule is UDP-only, process-attributed and repeated. Five UDP datagrams do not prove non-application C2, exfiltration, payload semantics or server receipt.",
            Severity = SeverityLevel.Low,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source","destination_or_host","process.name","process.id","udp.payload_length" },
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
            FalsePositives = new[] { "Five UDP datagrams do not prove non-application C2, exfiltration, payload semantics or server receipt. Authorized software distribution, administration and security testing may resemble this signal." },
            MinimumConfidence = 80,
            WindowThreshold = 5,
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
        private readonly Research666TimedWindow _timed = new();

        public R703_ScriptProcessRepeatedPublicUdpPayloadBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research696Evidence.RawPublicUdp(r, "powershell.exe", "pwsh.exe", "python.exe", "pythonw.exe", "rundll32.exe", "mshta.exe")
            || !_timed.Observe(r.Source+"|"+r.Destination+"|"+r.DestinationPort+"|"+r.ProcessId,
                r.Id, r.L4Len!.Value, context.TimestampUtc, 5, false, 500))
            return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2043", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "independent_udpburst_shape", "rule"),
                new DetectionEvidenceItem("outcome", "repeated_udp_payload_observation_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(context, SeverityLevel.Low,
                "Script-like process emits repeated raw UDP payloads to one public high-port peer observed; Five UDP datagrams do not prove non-application C2, exfiltration, payload semantics or server receipt.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "coherent-source-destination-or-sequence");
                }, count: 5, windowSeconds: 300);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
