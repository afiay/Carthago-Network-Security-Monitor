// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R211_PowershellGalleryExternalScriptPullRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R211_PowershellGalleryExternalScriptPullRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R211",
            Name: "PowerShell Gallery External Script Pull",
            Category: "CloudDev",
            Description: "Detects PowerShell-driven external script pulls from non-gallery hosts instead of broad install-module or downloadstring keyword matches.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R211.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R211",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Payload, RuleTelemetryKind.DevOpsAudit },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "http.path", "matched_conditions" },
            positiveConditions: new[]
            {
                "The calling process must look like PowerShell or pwsh.",
                "The request should pull a script or use explicit download-string style semantics.",
                "The host should be external and not the official PowerShell Gallery."
            },
            negativeConditions: new[]
            {
                "Do not alert on official PowerShell Gallery traffic.",
                "Do not alert on generic PowerShell web requests that do not retrieve scripts."
            },
            minimumConfidence: 84,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+host",
            falsePositives: new[] { "Approved automation can retrieve PowerShell scripts from sanctioned internal or third-party repositories." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive powershell external script pull sample", "negative official powershell gallery sample" });

        public R211_PowershellGalleryExternalScriptPullRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!IsPowerShellScriptPull(context.Record))
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "powershell_client,external_script_pull,non_gallery_host", "rule")
            };
            evidence.AddRange(AnalystContext(
                "A PowerShell process pulled script material from an external host that was not the official PowerShell Gallery.",
                "Severity is High because external PowerShell script pulls are a common execution vector for initial access, staging, and hands-on-keyboard tradecraft.",
                "Approved automation can retrieve scripts from sanctioned repositories. Validate repository ownership and script provenance before escalating.",
                "Review the PowerShell command line and retrieved script path if available.",
                "Confirm whether the script source is approved for the endpoint or workload."));

            return MatchHttpApi(
                context,
                SeverityLevel.High,
                "PowerShell external script pull observed",
                "PowerShellExternalScriptPull",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.22, "powershell-client");
                    confidence.AddEvidence(0.20, "external-script-pull");
                    confidence.AddEvidence(0.18, "non-gallery-host");
                },
                cooldownKey: $"{context.Record.Source}:{BestHost(context.Record)}");
        }
    }
}
