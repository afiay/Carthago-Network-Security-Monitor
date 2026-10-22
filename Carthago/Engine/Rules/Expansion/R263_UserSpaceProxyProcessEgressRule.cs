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
            var record = context.Record;
            if (!(IsOutboundExternal(record) && IsUserSpaceProxyProcess(record)))
                return NoMatch();

            var count = 1;
            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "UserSpaceProxy,evidence_gated,threshold_met", "rule"),
                new("rule.windowCount", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule")
            };
            evidence.AddRange(AnalystContext(
                "A known user-space proxy/tunnel process was observed making outbound external connections.",
                "Severity is Medium because ad-hoc proxies and tunnels can bypass normal network controls or create covert access paths.",
                "Approved remote support tunnels and developer tunnels such as sanctioned ngrok/cloudflared use can be legitimate.",
                "Verify the source host role, owner, and recent process/startup changes.",
                "Pivot on destination host, destination port, process name, and adjacent detections in the same time window.",
                "Tune approved business systems explicitly instead of weakening the rule globally."));

            return MatchEvasionInfra(
                context,
                SeverityLevel.Medium,
                "User-space proxy or tunnel process initiated external egress",
                "UserSpaceProxy",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "concrete-evidence");
                    confidence.AddEvidence(0.22, "source-context");
                    confidence.AddEvidence(0.18, "threshold-or-baseline");
                },
                count: count,
                window: Profile.Window,
                cooldownKey: $"{record.Source}:{BestHost(record)}:{record.DestinationPort ?? 0}:UserSpaceProxy");
        }
    }
}
