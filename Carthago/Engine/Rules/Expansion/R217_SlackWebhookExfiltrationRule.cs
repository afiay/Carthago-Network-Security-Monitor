// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R217_SlackWebhookExfiltrationRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R217_SlackWebhookExfiltrationRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R217",
            Name: "Slack Webhook Exfiltration",
            Category: "CloudDev",
            Description: "Detects POST requests to Slack webhook or file/message upload APIs from non-collaboration processes, instead of any generic Slack host match.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R217.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R217",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Payload, RuleTelemetryKind.CloudAudit },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "http.path", "matched_conditions" },
            positiveConditions: new[]
            {
                "The request must target an actual Slack webhook or upload/message API endpoint.",
                "The method must be POST.",
                "The calling process should not look like the normal Slack desktop client."
            },
            negativeConditions: new[]
            {
                "Do not alert on ordinary browser navigation to slack.com.",
                "Do not alert on Slack desktop client traffic."
            },
            minimumConfidence: 84,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+host+path",
            falsePositives: new[] { "Approved integrations and sanctioned automation can post to Slack webhooks or upload APIs intentionally." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive slack webhook exfil sample", "negative slack desktop client sample" });

        public R217_SlackWebhookExfiltrationRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!TryClassifySlackRequest(record, out var classifier))
                return NoMatch();

            if (ContainsAny(record.ProcessName, "slack"))
                return NoMatch();

            var exfilHint = HasSlackExfilHint(record) || TransferBytes(record) >= 50_000 || string.Equals(classifier, "slack-webhook", StringComparison.OrdinalIgnoreCase);
            if (!exfilHint)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("cloud.provider", classifier, "cloud"),
                new("matched_conditions", "slack_webhook_or_api_post,non_slack_process,exfil_like_payload", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The HTTP POST targeted a real Slack webhook or upload/message API endpoint from a process that did not look like the normal Slack client.",
                "Severity is High because webhook or upload-style Slack traffic from arbitrary processes is a common collaboration-channel exfiltration pattern.",
                "Approved integrations and automation can legitimately post to Slack. Validate the integration owner and payload purpose before escalating.",
                "Review the calling process and whether the payload included files, attachments, or message content.",
                "Confirm whether the Slack webhook or app endpoint is approved for the source system."));

            return MatchHttpApi(
                context,
                SeverityLevel.High,
                "Slack webhook or upload-style exfiltration pattern observed",
                "SlackWebhookExfiltration",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.22, "slack-webhook-or-api-post");
                    confidence.AddEvidence(0.18, "non-slack-process");
                    confidence.AddEvidence(0.16, "exfil-like-payload");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{HttpPath(record)}");
        }
    }
}
