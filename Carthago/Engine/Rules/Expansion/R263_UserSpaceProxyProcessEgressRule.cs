// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R263_UserSpaceProxyProcessEgressRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R263_UserSpaceProxyProcessEgressRule : EvasionInfraPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R263",
            Name: "User-Space Proxy Process Egress",
            Category: "EvasionInfra",
            Description: "Detects user-space proxy process egress only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R263.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvasionInfraProfile(
            ruleId: "R263",
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
            falsePositives: new[] { "Approved remote support tunnels and developer tunnels such as sanctioned ngrok/cloudflared use can be legitimate." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "Threshold", "WindowSeconds" },
            requiredTests: new[] { "positive R263 evidence-gated sample", "negative R263 descriptor-only sample", "negative R263 missing telemetry sample" });

        public R263_UserSpaceProxyProcessEgressRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch261265Evidence.ProxyProcessEgress(r, out var process)) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "exact_proxy_process,typed_external_tcp_flow", "rule"),
                new("process.basename", process, "process")
            };
            evidence.AddRange(AnalystContext("An exact known proxy/tunnel process basename co-occurs with external TCP egress.",
                "Process association depends on unverified capture enrichment and does not prove policy bypass.",
                "Sanctioned remote-support and development tunnels are common false positives.",
                "Check process ownership and explicit approved-process policy."));
            return MatchEvasionInfra(context, SeverityLevel.Medium, "Proxy/tunnel process co-observed with external TCP egress",
                "UserSpaceProxy", evidence, c => { c.AddEvidence(0.34, "exact-process"); c.AddEvidence(0.22, "typed-tcp-egress"); c.AddEvidence(0.18, "endpoint"); },
                cooldownKey: r.Source + "|" + r.Destination + "|" + process);
        }
    }
}
