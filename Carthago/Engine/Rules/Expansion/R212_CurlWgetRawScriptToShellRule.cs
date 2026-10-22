// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R212_CurlWgetRawScriptToShellRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R212_CurlWgetRawScriptToShellRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R212",
            Name: "Curl Wget Raw Script To Shell",
            Category: "CloudDev",
            Description: "Detects curl or wget style pipe-to-shell retrieval from raw script sources instead of any mention of curl, wget, or GitHub raw text.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R212.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R212",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Payload, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "http.path", "matched_conditions" },
            positiveConditions: new[]
            {
                "The telemetry must reflect curl or wget style retrieval.",
                "Pipe-to-shell semantics such as | sh or | bash must be present.",
                "The source should be a raw script host or explicit script path."
            },
            negativeConditions: new[]
            {
                "Do not alert on plain file downloads without pipe-to-shell behavior.",
                "Do not alert on generic raw Git browsing by browsers."
            },
            minimumConfidence: 90,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+host",
            falsePositives: new[] { "Some administrative bootstrap workflows intentionally use curl or wget piped into shell, but this should be tightly controlled." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive curl raw script to shell sample", "negative raw script download sample" });

        public R212_CurlWgetRawScriptToShellRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!IsCurlWgetScriptToShell(context.Record))
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "curl_or_wget_client,pipe_to_shell,raw_script_source", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The traffic reflected curl or wget style script retrieval combined with explicit pipe-to-shell execution semantics.",
                "Severity is Critical because pipe-to-shell retrieval is a high-fidelity execution pattern for bootstrap malware, installers, and hands-on-keyboard intrusion activity.",
                "Some tightly controlled bootstrap workflows may intentionally use this pattern, but it should be rare and well understood.",
                "Review the parent process and the exact script source that was executed.",
                "Confirm whether the script host and retrieval pattern are approved for the endpoint."));

            return MatchHttpApi(
                context,
                SeverityLevel.Critical,
                "Curl/wget raw script to shell pattern observed",
                "CurlWgetScriptToShell",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.26, "curl-or-wget-client");
                    confidence.AddEvidence(0.24, "pipe-to-shell");
                    confidence.AddEvidence(0.20, "raw-script-source");
                },
                cooldownKey: $"{context.Record.Source}:{BestHost(context.Record)}");
        }
    }
}
