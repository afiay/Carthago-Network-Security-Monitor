// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R499_RemoteDesktopFileTransferBurstRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R499_RemoteDesktopFileTransferBurstRule : DataLossStagingPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R499",
            Name: "Remote Desktop File Transfer Burst",
            Category: "DataLossStaging",
            Description: "Detects Remote Desktop File Transfer Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R499.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R499",
            Name = "Remote Desktop File Transfer Burst",
            Category = "DataLossStaging",
            Description = "Detects Remote Desktop File Transfer Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Process, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "external_destination_or_upload_host", "file_or_payload_indicator" },
            EvidenceFields = new[] { "http.path", "file.name", "process.name", "matched_conditions" },
            PositiveConditions = new[] { "Remote Desktop File Transfer Burst requires observable DataLossStaging telemetry and will not match descriptor text alone.", "Source and destination, host, process, protocol, path, port, or payload evidence must be present.", "The configured signal count and time-window threshold must be satisfied before a DetectionEvent is emitted." },
            NegativeConditions = new[] { "Do not match on product names, rule names, documentation text, or generic banners alone.", "Do not match when source/destination context is absent or when the traffic is inside an approved management path.", "Do not match known monitoring, backup, CI/CD, inventory, scanner, or administrative workflows unless rule-specific high-risk evidence remains." },
            FalsePositives = new[] { "Approved backup, DLP testing, cloud-drive sync, software deployment, and ticket-upload workflows can resemble staging; approve known tools and destinations." },
            TextIndicators = new[] { "remote desktop file transfer burst", "remote", "desktop", "file", "transfer", "upload", "post", "export", "archive", "base64", "secret", "password", "private key", "cookie", "clipboard" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = new[] { "rclone", "rsync", "scp", "sftp", "winscp", "curl", "wget", "powershell", "pwsh", "python", "node", "chrome" },
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 84,
            WindowThreshold = 4,
            Window = TimeSpan.FromMinutes(10),
            Cooldown = TimeSpan.FromMinutes(35),
            DistinctBy = "source+destination+datalossstaging+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedCloudStorage", "ApprovedBackupTools", "SensitiveFilenamePatterns", "UploadByteThreshold" },
            RequiredTests = new[] { "positive R499 evidence-gated sample", "negative R499 descriptor-only sample", "negative R499 missing telemetry sample", "negative R499 approved-admin sample" },
            RequireOutboundExternal = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R499_RemoteDesktopFileTransferBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
            => EvaluateSpec(context, Spec);
    }
}
