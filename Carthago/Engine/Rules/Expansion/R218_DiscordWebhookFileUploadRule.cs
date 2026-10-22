// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R218_DiscordWebhookFileUploadRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R218_DiscordWebhookFileUploadRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R218",
            Name: "Discord Webhook File Upload",
            Category: "CloudDev",
            Description: "Detects concrete Discord webhook or attachment upload requests with file-transfer context, while suppressing ordinary Discord client traffic and loose hostname matches.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R218.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R218",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Payload, RuleTelemetryKind.CloudAudit },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "http.path", "host.classifier", "matched_conditions" },
            positiveConditions: new[]
            {
                "The request must target an exact Discord webhook or attachment upload endpoint.",
                "The request should include multipart, attachment, filename, or meaningful upload volume context.",
                "Ordinary Discord desktop-client traffic should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on generic discord.com browsing or message traffic without upload semantics.",
                "Do not alert on Discord desktop-client uploads unless the transfer context is unusually strong."
            },
            minimumConfidence: 84,
            threshold: null,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: null,
            falsePositives: new[] { "Approved build, alerting, or collaboration bots can upload artifacts to Discord webhooks intentionally." },
            tuningKnobs: new[] { "Mode", "MinimumPayloadBytes", "CooldownSeconds" },
            requiredTests: new[] { "positive discord webhook upload sample", "negative discord desktop client sample" });

        public R218_DiscordWebhookFileUploadRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!TryClassifyDiscordWebhookUpload(record, out var classifier))
                return NoMatch();

            var bytes = TransferBytes(record);
            var minimumPayloadBytes = IntSetting(Descriptor.RuleId, "MinimumPayloadBytes", 50_000, 8_000, 50_000_000);
            var uploadHint = HasUploadMetadata(record) || ContainsAny(Text(record), "payload_json", "attachments", "filename=", "multipart/form-data");
            if (!uploadHint && bytes < minimumPayloadBytes)
                return NoMatch();

            if (IsLikelyCollaborationClientProcess(record.ProcessName) && !uploadHint && bytes < minimumPayloadBytes * 2L)
                return NoMatch();

            var matchedConditions = new List<string> { "discord_exact_upload_endpoint", "supporting_upload_context" };
            if (uploadHint) matchedConditions.Add("multipart_or_attachment_hint");
            if (bytes >= minimumPayloadBytes) matchedConditions.Add("non_trivial_payload");
            if (!IsLikelyCollaborationClientProcess(record.ProcessName)) matchedConditions.Add("non_discord_process");

            var evidence = new List<DetectionEvidenceItem>
            {
                new("host.classifier", classifier, "cloud"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                "The HTTP request targeted an exact Discord webhook or attachment endpoint with file-upload context.",
                "Severity is High because Discord webhook uploads are a common collaboration-channel exfiltration path when driven by arbitrary processes or automation.",
                "Approved webhook bots and sanctioned collaboration automations can upload content intentionally. Validate the webhook owner and calling process before escalating.",
                "Review whether the request used a webhook token or a channel attachment flow.",
                "Correlate with endpoint telemetry to determine which file or payload was staged for upload."));

            return MatchCloudDev(
                context,
                SeverityLevel.High,
                "Discord webhook or attachment upload observed",
                "DiscordWebhookUpload",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "discord-exact-upload-endpoint");
                    if (uploadHint) confidence.AddEvidence(0.20, "multipart-or-attachment-hint");
                    if (!IsLikelyCollaborationClientProcess(record.ProcessName)) confidence.AddEvidence(0.16, "non-discord-process");
                    if (bytes >= minimumPayloadBytes) confidence.AddEvidence(0.10, "non-trivial-payload");
                },
                cooldownKey: $"{record.Source}:{ProviderIdentity(BestHost(record))}:{classifier}");
        }
    }
}
