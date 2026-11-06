// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R1464.
using System;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R765_LinuxRemoteServiceAttemptThenShellEgressRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R765",
            Name: "Public Linux-service attempt followed by shell/tool egress",
            Category: "LateralMovement",
            Description: "A public-to-private TCP SYN to a common Linux remote/service port is followed within 90 seconds by outbound public traffic from the same private host attributed to bash, sh, zsh, curl, wget, Python or Python3. Service crash, shell parentage, successful login/exploit, causal linkage and compromise are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R765.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R765",
            Name = "Public Linux-service attempt followed by shell/tool egress",
            Category = "LateralMovement",
            Description = "workbook.R1464: the source analytic links remote-service access with crash/restart or service-spawned shell behavior. Carthago retains only the bounded network sequence: public service connection attempt followed by shell/tool-attributed egress from the same host.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "public_source", "private_destination", "tcp.flags", "service.port", "follow_on_source", "follow_on_process.name" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed producer fields and this independent rule-specific predicate.",
                "Process identity, where used, is best-effort local tuple enrichment rather than authenticated endpoint identity.",
                "Stateful rules accept unique packet IDs in monotonic UTC order inside bounded rule-owned windows."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, malformed endpoints and Info-only assertions.",
                "Reject duplicate packet IDs, reverse time, expired sequences and cooldown repeats.",
                "Do not infer file access, credentials, command-line arguments, successful authentication, exploit success, C2 control, transfer completion or compromise."
            },
            FalsePositives = new[] { "Public-facing services, vulnerability scanning, normal administration and unrelated automation on the same host can create coincidental temporal correlation." },
            MinimumConfidence = 80,
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(90),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "private_linux_service_host+public_attempt+shell_tool_egress_sequence",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive shaped sample and rule-specific benign near miss",
                "missing and contradictory telemetry",
                "duplicate ID, reverse-time and expiry where stateful",
                "cooldown suppression and recovery",
                "privacy, non-convergence, Candidate Shadow and registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research756HostSequenceWindow _sequence = new();

        public R765_LinuxRemoteServiceAttemptThenShellEgressRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (Research756Evidence.LinuxRemoteServiceTrigger(r))
                {
                    _sequence.Observe(r.Destination!, r.Id, context.TimestampUtc, true, 90);
                    return NoMatch();
                }
            
                if (!Research756Evidence.LinuxShellEgress(r)
                    || !_sequence.Observe(r.Source!, r.Id, context.TimestampUtc, false, 90))
                    return NoMatch();

            var cool = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (cool == WebSignatureObservation.None) return NoMatch();
            if (cool == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1464", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "public_linux_service_attempt_then_shell_tool_egress", "rule"),
                new DetectionEvidenceItem("outcome", "temporal_network_sequence_only_exploit_and_causality_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Public Linux-service connection attempt followed by shell/tool-attributed egress from the same private host observed; login, exploit success, causality and compromise are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 2,
                windowSeconds: 90);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
