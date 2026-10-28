// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R209_NpmInstallScriptBeaconPatternRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R209_NpmInstallScriptBeaconPatternRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R209",
            Name: "NPM Install Script Beacon Pattern",
            Category: "CloudDev",
            Description: "Detects outbound npm or node install-script beaconing to non-official external hosts instead of matching generic postinstall text.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R209.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R209",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Payload, RuleTelemetryKind.DevOpsAudit },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "http.path", "matched_conditions" },
            positiveConditions: new[]
            {
                "The process or user agent must look like npm, pnpm, yarn, or node.",
                "Install-script indicators such as postinstall or preinstall must be present.",
                "The destination should be an external non-official host."
            },
            negativeConditions: new[]
            {
                "Do not alert on ordinary package download traffic without install-script indicators.",
                "Do not alert on official registry traffic."
            },
            minimumConfidence: 84,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+host",
            falsePositives: new[] { "Legitimate internal packages can use install hooks, but they should not normally beacon to unfamiliar external hosts." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive npm install script beacon sample", "negative normal npm download sample" });

        public R209_NpmInstallScriptBeaconPatternRule() : base(Rule, Profile) { }

        private readonly NetworkBatch201205Window _observations = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!NetworkBatch206215Evidence.NpmCallback(context.Record)
                || !_observations.Observe(context.Record,
                    $"{Descriptor.RuleId}:{context.Record.Source}:{context.Record.HttpHost}",
                    context.Record.HttpHost ?? "", context.TimestampUtc,
                    TimeSpan.FromMinutes(15), 0, out _, out _))
                return NoMatch();

            var host = BestHost(context.Record);
            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "npm_or_node_client,install_script_indicator,external_nonofficial_host", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The traffic looked like an npm or node install-script callback to a non-official external host.",
                "Severity is High because dependency install hooks are a common supply-chain execution vector and should not ordinarily beacon outward.",
                "Approved private packages may legitimately use install hooks, but external callback destinations should be rare. Validate package ownership before escalating.",
                "Review the package manager process, package name, and install script content if available.",
                "Confirm whether the external host is associated with an approved package workflow."));

            return MatchHttpApi(
                context,
                SeverityLevel.High,
                "NPM install-script beacon pattern observed",
                "NpmInstallScriptBeacon",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.22, "npm-or-node-client");
                    confidence.AddEvidence(0.20, "install-script-indicator");
                    confidence.AddEvidence(0.18, "external-nonofficial-host");
                },
                cooldownKey: $"{context.Record.Source}:{host}");
        }
    }
}
