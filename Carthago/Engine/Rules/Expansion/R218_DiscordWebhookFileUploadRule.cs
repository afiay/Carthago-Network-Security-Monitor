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

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch216220Evidence.Discord(record, out var classifier)
                || IsLikelyCollaborationClientProcess(record.ProcessName)
                || !_replay.Observe(record, context.TimestampUtc))
                return NoMatch();
            var evidence = new List<DetectionEvidenceItem>
            {
                new("host.classifier", classifier, "cloud"),
                new("matched_conditions", "typed_http,exact_discord_endpoint,declared_upload_context", "rule")
            };
            evidence.AddRange(AnalystContext(
                "A parsed Discord webhook or channel attachment POST included multipart or declared large-body context.",
                "This request shape is compatible with data transfer, but delivery and exfiltration are not proven.",
                "Approved collaboration bots may send files through these endpoints.",
                "Correlate with endpoint process and file activity.",
                "Confirm the webhook or bot is authorized for the source."));
            return MatchHttpApi(context, SeverityLevel.High,
                "Discord webhook or attachment request observed", "DiscordWebhookUpload",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.24, "discord-exact-upload-endpoint");
                    confidence.AddEvidence(0.20, "declared-upload-context");
                    confidence.AddEvidence(0.16, "non-discord-process");
                    confidence.AddEvidence(0.10, "request-shape");
                }, cooldownKey: NetworkBatch216220Evidence.SafeKey(record));
        }
    }
}

