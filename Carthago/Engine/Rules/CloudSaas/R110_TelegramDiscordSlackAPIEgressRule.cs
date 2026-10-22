// SPDX-License-Identifier: MIT
// File: Engine/Rules/CloudSaas/R110_TelegramDiscordSlackAPIEgressRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.CloudSaas
{
    public sealed class R110_TelegramDiscordSlackAPIEgressRule : CloudSaasPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R110",
            Name: "Telegram / Discord / Slack API Egress",
            Category: "CloudSaas",
            Description: "Detects suspicious chat-platform API or webhook egress when the host and URI map to actual message, file, or webhook paths rather than generic collaboration traffic.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R110.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudSaasProfile(
            ruleId: "R110",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[]
            {
                "cloud.host", "http.uri", "host.classifier", "flow.bytes", "matched_conditions"
            },
            positiveConditions: new[]
            {
                "The destination must be a real chat API or webhook path, not just a collaboration hostname.",
                "The request should include upload, send, attachment, webhook, or similarly relevant action context.",
                "Generic client or Teams-like browsing should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on generic Teams or collaboration web traffic.",
                "Do not alert on Slack or Discord API paths that lack message, file, or webhook action context.",
                "Do not alert on tiny client chatter without supporting exfil indicators."
            },
            minimumConfidence: 78,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+provider",
            falsePositives: new[]
            {
                "Approved chat bots, alerting hooks, and automation can legitimately use these APIs.",
                "Native collaboration clients can generate benign API traffic when users are active."
            },
            tuningKnobs: new[] { "Mode", "MinimumPayloadBytes", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive webhook-or-file-send sample",
                "negative generic collaboration traffic sample",
                "negative unsupported API-path sample"
            });

        public R110_TelegramDiscordSlackAPIEgressRule()
            : base(Rule, Profile)
        {
        }

        protected override string? InvestigationHintOverride
            => "Review whether the request targeted a webhook, file-upload, or message-send path and whether the source process is approved to automate chat-platform egress.";

        protected override string? TuningHintOverride
            => "Tune payload and process thresholds, but keep exact API or webhook path classification mandatory to avoid generic collaboration noise.";

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = BestHost(record);
            if (string.IsNullOrWhiteSpace(host) || !IsInternalAddress(record.Source) || !IsExternalAddress(record.Destination))
                return NoMatch();

            if (!TryClassifyChatApiRequest(host, record, out var classifier))
                return NoMatch();

            var bytes = TransferBytes(record);
            var minimumPayloadBytes = IntSetting(Descriptor.RuleId, "MinimumPayloadBytes", 150_000, 8_000, 50_000_000);
            var exfilHint = HasChatExfilHint(record) || HasUploadMetadata(record);
            var automation = IsLikelyAutomationProcess(record);
            if (!exfilHint && !automation && bytes < minimumPayloadBytes)
                return NoMatch();

            if (IsLikelyCollaborationClientProcess(record.ProcessName) && !exfilHint && bytes < minimumPayloadBytes * 2L)
                return NoMatch();

            var matchedConditions = new List<string> { "chat_api_or_webhook_path", "supporting_exfil_context" };
            if (exfilHint) matchedConditions.Add("message_or_file_action");
            if (automation) matchedConditions.Add("automation_process");
            if (bytes >= minimumPayloadBytes) matchedConditions.Add("non_trivial_payload");

            var whyMatched = $"{record.Source} contacted {classifier} on {host} with {bytes} bytes of request volume.";
            var severityReason = "Severity is High because the request targeted a chat-platform webhook or file/message API path with supporting exfiltration context.";
            var falsePositives = "Approved alerting bots and automation can legitimately use chat APIs. Validate the webhook ownership, bot token scope, and source process before escalating.";

            var evidence = new List<DetectionEvidenceItem>
            {
                new("host.classifier", classifier, "cloud"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                whyMatched,
                severityReason,
                falsePositives,
                "Validate whether the webhook, bot token, or API action is approved for this host or user.",
                "Review the request path for file-send, attachment, or message-post operations.",
                "Correlate with endpoint telemetry to determine what content may have been staged for chat-platform egress."));

            return MatchCloud(
                context,
                SeverityLevel.High,
                $"Chat-platform API egress observed via {classifier}",
                host,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "exact-chat-api-classification");
                    if (exfilHint) confidence.AddEvidence(0.20, "message-or-file-action");
                    if (automation) confidence.AddCorrelation(0.16, "automation-process");
                    if (bytes >= minimumPayloadBytes) confidence.AddEvidence(0.10, "non-trivial-payload");
                },
                cooldownKey: $"{record.Source}:{ProviderIdentity(host)}");
        }
    }
}
