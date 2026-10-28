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

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch216220Evidence.Telegram(record)
                || IsLikelyCollaborationClientProcess(record.ProcessName)
                || !_replay.Observe(record, context.TimestampUtc))
                return NoMatch();
            var evidence = new List<DetectionEvidenceItem>
            {
                new("host.classifier", "telegram-senddocument", "cloud"),
                new("matched_conditions", "typed_http,exact_bot_senddocument,declared_upload_context", "rule")
            };
            evidence.AddRange(AnalystContext(
                "A parsed Telegram Bot API sendDocument POST included multipart or declared large-body context.",
                "The request indicates attempted document transfer, not confirmed delivery or exfiltration.",
                "Approved reporting and incident-response bots may send documents.",
                "Correlate with endpoint process and file activity.",
                "Verify bot authorization through independent audit evidence."));
            return MatchHttpApi(context, SeverityLevel.High,
                "Telegram Bot API document request observed", "TelegramBotSendDocument",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.24, "telegram-senddocument-endpoint");
                    confidence.AddEvidence(0.20, "declared-document-context");
                    confidence.AddEvidence(0.16, "non-telegram-process");
                    confidence.AddEvidence(0.10, "request-shape");
                }, cooldownKey: NetworkBatch216220Evidence.SafeKey(record));
        }
    }
}

