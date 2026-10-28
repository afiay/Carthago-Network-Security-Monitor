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

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch216220Evidence.Slack(record, out var classifier)
                || ContainsAny(record.ProcessName, "slack")
                || !_replay.Observe(record, context.TimestampUtc))
                return NoMatch();
            var evidence = new List<DetectionEvidenceItem>
            {
                new("cloud.provider", classifier, "cloud"),
                new("matched_conditions", "typed_http,exact_slack_post,declared_upload_context,non_slack_process", "rule")
            };
            evidence.AddRange(AnalystContext(
                "A parsed Slack webhook or file-upload POST included multipart or declared large-body context.",
                "This is a potential collaboration-channel transfer, not proof of exfiltration or successful delivery.",
                "Approved integration and incident-response bots can post the same request shapes.",
                "Correlate with endpoint file activity and application audit logs.",
                "Confirm whether this integration and source process are approved."));
            return MatchHttpApi(context, SeverityLevel.High,
                "Slack webhook or file-upload request observed", "SlackWebhookExfiltration",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.22, "slack-webhook-or-api-post");
                    confidence.AddEvidence(0.18, "non-slack-process");
                    confidence.AddEvidence(0.16, "declared-upload-context");
                }, cooldownKey: NetworkBatch216220Evidence.SafeKey(record));
        }
    }
}

