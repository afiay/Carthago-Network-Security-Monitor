// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R219_TelegramBotApiSendDocumentRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R219_TelegramBotApiSendDocumentRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R219",
            Name: "Telegram Bot API Send Document",
            Category: "CloudDev",
            Description: "Detects exact Telegram Bot API sendDocument requests with document-upload context, instead of any generic api.telegram.org or sendMessage traffic.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R219.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R219",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Payload, RuleTelemetryKind.CloudAudit },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "http.path", "host.classifier", "matched_conditions" },
            positiveConditions: new[]
            {
                "The request must target the exact Telegram Bot API sendDocument endpoint.",
                "The request should include document or multipart upload context rather than simple bot messaging.",
                "Ordinary Telegram client traffic should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on api.telegram.org requests that do not hit sendDocument.",
                "Do not alert on Telegram desktop traffic without document-upload semantics."
            },
            minimumConfidence: 84,
            threshold: null,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: null,
            falsePositives: new[] { "Approved automation or alerting bots can legitimately send documents through Telegram." },
            tuningKnobs: new[] { "Mode", "MinimumPayloadBytes", "CooldownSeconds" },
            requiredTests: new[] { "positive telegram sendDocument sample", "negative telegram sendMessage sample" });

        public R219_TelegramBotApiSendDocumentRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!TryClassifyTelegramDocumentSend(record, out var classifier))
                return NoMatch();

            var bytes = TransferBytes(record);
            var minimumPayloadBytes = IntSetting(Descriptor.RuleId, "MinimumPayloadBytes", 50_000, 8_000, 50_000_000);
            var documentHint = HasUploadMetadata(record) || ContainsAny(Text(record), "name=\"document\"", "document=", "sendDocument", "attach://", "filename=");
            if (!documentHint && bytes < minimumPayloadBytes)
                return NoMatch();

            if (IsLikelyCollaborationClientProcess(record.ProcessName) && !documentHint && bytes < minimumPayloadBytes * 2L)
                return NoMatch();

            var matchedConditions = new List<string> { "telegram_senddocument_endpoint", "supporting_document_context" };
            if (documentHint) matchedConditions.Add("document_or_multipart_hint");
            if (bytes >= minimumPayloadBytes) matchedConditions.Add("non_trivial_payload");
            if (!IsLikelyCollaborationClientProcess(record.ProcessName)) matchedConditions.Add("non_telegram_process");

            var evidence = new List<DetectionEvidenceItem>
            {
                new("host.classifier", classifier, "cloud"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                "The HTTP request targeted Telegram's exact sendDocument bot endpoint with document-upload semantics.",
                "Severity is High because Telegram bot document uploads can move files out of the environment over a collaboration channel with minimal user interaction.",
                "Approved workflow automation may legitimately send reports or logs through Telegram bots. Validate bot ownership and the calling process before escalating.",
                "Review the bot path and payload shape to confirm document transfer rather than routine messaging.",
                "Correlate with endpoint telemetry to determine which file or archive was staged for upload."));

            return MatchCloudDev(
                context,
                SeverityLevel.High,
                "Telegram Bot API document upload observed",
                "TelegramBotSendDocument",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "telegram-senddocument-endpoint");
                    if (documentHint) confidence.AddEvidence(0.20, "document-or-multipart-hint");
                    if (!IsLikelyCollaborationClientProcess(record.ProcessName)) confidence.AddEvidence(0.16, "non-telegram-process");
                    if (bytes >= minimumPayloadBytes) confidence.AddEvidence(0.10, "non-trivial-payload");
                },
                cooldownKey: $"{record.Source}:{ProviderIdentity(BestHost(record))}:{classifier}");
        }
    }
}
