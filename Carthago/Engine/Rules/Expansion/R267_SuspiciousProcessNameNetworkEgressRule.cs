// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R267_SuspiciousProcessNameNetworkEgressRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R267_SuspiciousProcessNameNetworkEgressRule : EvasionInfraPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R267",
            Name: "Suspicious Process Name Network Egress",
            Category: "EvasionInfra",
            Description: "Detects suspicious process name network egress only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R267.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvasionInfraProfile(
            ruleId: "R267",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_process_or_info" },
            evidenceFields: new[] { "network.source", "network.destination", "process.name", "event.info", "matched_conditions" },
            positiveConditions: new[]
            {
                "The rule must observe concrete telemetry evidence tied to the named behavior.",
                "The event must include a source and either a destination/host, process, protocol, or pipeline component.",
                "Generic descriptor text alone must not produce a match."
            },
            negativeConditions: new[]
            {
                "Do not alert when the required telemetry fields are absent.",
                "Do not alert on generic logs that mention the concept but lack network/process/pipeline evidence."
            },
            minimumConfidence: 82,
            threshold: 1,
            window: TimeSpan.FromMinutes(20),
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+destination+behavior",
            falsePositives: new[] { "Some internal tools may have poor names; whitelist by signed path/hash in the endpoint layer rather than suppressing broadly." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "Threshold", "WindowSeconds" },
            requiredTests: new[] { "positive R267 evidence-gated sample", "negative R267 descriptor-only sample", "negative R267 missing telemetry sample" });

        public R267_SuspiciousProcessNameNetworkEgressRule() : base(Rule, Profile) { }

        private readonly NetworkBatch266270Evidence.DistinctWindow _observed = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch266270Evidence.SuspiciousName(r, out var process)) return NoMatch();
            var key = r.Source + "|" + r.ProcessId + "|" + r.Destination + "|" + process;
            if (_observed.Observe(r, context.TimestampUtc, key, TimeSpan.FromMinutes(20)) == 0) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "typed_external_tcp,exact_masquerade_basename", "rule"),
                new("process.nameCategory", "exact_masquerade_candidate", "rule")
            };
            evidence.AddRange(AnalystContext("An exactly matched suspicious process basename was co-observed with external TCP egress.",
                "A suspicious name alone does not prove executable identity, signing status or malicious execution.",
                "Poorly named internal applications and authorized security tests can resemble masquerading.",
                "Confirm process path, signer and hash using trusted endpoint telemetry."));
            return MatchEvasionInfra(context, SeverityLevel.High,
                "Masquerade-like process name with external TCP egress (identity unverified)", "SuspiciousProcess",
                evidence, c => { c.AddEvidence(0.34, "typed-external-tcp"); c.AddEvidence(0.22, "exact-process-basename"); c.AddEvidence(0.18, "distinct-observation"); },
                cooldownKey: key + ":masquerade");
        }
    }
}
