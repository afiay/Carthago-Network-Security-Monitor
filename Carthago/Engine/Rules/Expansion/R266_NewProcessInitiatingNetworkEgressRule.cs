// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R266_NewProcessInitiatingNetworkEgressRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R266_NewProcessInitiatingNetworkEgressRule : EvasionInfraPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R266",
            Name: "New Process Initiating Network Egress",
            Category: "EvasionInfra",
            Description: "Detects new process initiating network egress only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R266.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvasionInfraProfile(
            ruleId: "R266",
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
            minimumConfidence: 75,
            threshold: 1,
            window: TimeSpan.FromMinutes(20),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+destination+behavior",
            falsePositives: new[] { "Software installs, updates, and newly deployed business applications can naturally create first-seen egress." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "Threshold", "WindowSeconds" },
            requiredTests: new[] { "positive R266 evidence-gated sample", "negative R266 descriptor-only sample", "negative R266 missing telemetry sample" });

        public R266_NewProcessInitiatingNetworkEgressRule() : base(Rule, Profile) { }

        private readonly NetworkBatch266270Evidence.FirstObserved _seen = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch266270Evidence.NewProcessEgress(r, out var process)) return NoMatch();
            var key = r.Source + "|" + r.ProcessId + "|" + process;
            if (!_seen.Observe(r, context.TimestampUtc, key)) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "typed_external_tcp,attributed_process,instance_first_observed", "rule"),
                new("process.identityHash", NetworkBatch131135Evidence.Fingerprint(key), "rule"),
                new("process.baselineStatus", "first_in_detector_instance_not_launch_or_approved_baseline", "rule")
            };
            evidence.AddRange(AnalystContext("A source/PID/process combination was first observed on an external TCP flow in this detector instance.",
                "First observation is not process creation, approved-baseline novelty or evidence of compromise.",
                "New software and routine deployment commonly create first-observed process traffic.",
                "Confirm process provenance with trusted endpoint events before escalation."));
            return MatchEvasionInfra(context, SeverityLevel.Low,
                "Process first observed with external TCP flow (launch unverified)", "NewProcessEgress",
                evidence, c => { c.AddEvidence(0.34, "typed-external-tcp"); c.AddEvidence(0.22, "process-identity"); c.AddEvidence(0.18, "instance-first-observed"); },
                cooldownKey: key + ":first-observed");
        }
    }
}
