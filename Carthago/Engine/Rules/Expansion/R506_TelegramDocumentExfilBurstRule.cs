// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R506_TelegramDocumentExfilBurstRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R506_TelegramDocumentExfilBurstRule : DataLossStagingPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R506",
            Name: "Telegram Document Exfil Burst",
            Category: "DataLossStaging",
            Description: "Detects Telegram Document Exfil Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R506.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R506",
            Name = "Telegram Document Exfil Burst",
            Category = "DataLossStaging",
            Description = "Detects Telegram Document Exfil Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Process, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "external_destination_or_upload_host", "file_or_payload_indicator" },
            EvidenceFields = new[] { "http.path", "file.name", "process.name", "matched_conditions" },
            PositiveConditions = new[] { "Telegram Document Exfil Burst requires observable DataLossStaging telemetry and will not match descriptor text alone.", "Source and destination, host, process, protocol, path, port, or payload evidence must be present.", "The configured signal count and time-window threshold must be satisfied before a DetectionEvent is emitted." },
            NegativeConditions = new[] { "Do not match on product names, rule names, documentation text, or generic banners alone.", "Do not match when source/destination context is absent or when the traffic is inside an approved management path.", "Do not match known monitoring, backup, CI/CD, inventory, scanner, or administrative workflows unless rule-specific high-risk evidence remains." },
            FalsePositives = new[] { "Approved backup, DLP testing, cloud-drive sync, software deployment, and ticket-upload workflows can resemble staging; approve known tools and destinations." },
            TextIndicators = new[] { "telegram document exfil burst", "telegram", "document", "exfil", "upload", "post", "export", "archive", "base64", "secret", "password", "private key", "cookie", "clipboard" },
            HostIndicators = new[] { "api.telegram.org", "telegram.org" },
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = new[] { "rclone", "rsync", "scp", "sftp", "winscp", "curl", "wget", "powershell", "pwsh", "python", "node", "chrome" },
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = Array.Empty<int>(),
            MinimumBytes = 5242880L,
            MinimumSignals = 2,
            MinimumConfidence = 84,
            WindowThreshold = 4,
            Window = TimeSpan.FromMinutes(10),
            Cooldown = TimeSpan.FromMinutes(35),
            DistinctBy = "source+destination+datalossstaging+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedCloudStorage", "ApprovedBackupTools", "SensitiveFilenamePatterns", "UploadByteThreshold" },
            RequiredTests = new[] { "positive R506 evidence-gated sample", "negative R506 descriptor-only sample", "negative R506 missing telemetry sample", "negative R506 approved-admin sample" },
            RequireOutboundExternal = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R506_TelegramDocumentExfilBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
            => EvaluateSpec(context, Spec);
    }
}
