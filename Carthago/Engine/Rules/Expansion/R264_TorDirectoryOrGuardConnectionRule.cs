// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R264_TorDirectoryOrGuardConnectionRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R264_TorDirectoryOrGuardConnectionRule : EvasionInfraPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R264",
            Name: "Tor Directory Or Guard Connection",
            Category: "EvasionInfra",
            Description: "Detects tor directory or guard connection only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R264.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvasionInfraProfile(
            ruleId: "R264",
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
            falsePositives: new[] { "Security research, privacy tooling, and sanctioned Tor tests may legitimately contact Tor infrastructure." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "Threshold", "WindowSeconds" },
            requiredTests: new[] { "positive R264 evidence-gated sample", "negative R264 descriptor-only sample", "negative R264 missing telemetry sample" });

        public R264_TorDirectoryOrGuardConnectionRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch261265Evidence.TorProcessEgress(r, out var process)) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "exact_tor_process,typed_external_tcp_flow", "rule"),
                new("process.basename", process, "process")
            };
            evidence.AddRange(AnalystContext("An exact Tor-process basename co-occurs with an external TCP connection.",
                "Neither port nor process alone establishes a directory/guard role or an active Tor circuit.",
                "Approved research and privacy tools may legitimately generate the same telemetry.",
                "Corroborate against a trusted Tor relay inventory and approved process ownership."));
            return MatchEvasionInfra(context, SeverityLevel.High, "Tor-process external TCP egress (guard role unverified)",
                "Tor", evidence, c => { c.AddEvidence(0.34, "exact-tor-process"); c.AddEvidence(0.22, "typed-tcp-egress"); c.AddEvidence(0.18, "endpoint"); },
                cooldownKey: r.Source + "|" + r.Destination + ":tor-process");
        }
    }
}
