// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R402_AsyncRATTelegramC2PatternRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R402_AsyncRATTelegramC2PatternRule : MalwareC2PrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R402",
            Name: "AsyncRAT Telegram C2 Pattern",
            Category: "MalwareC2",
            Description: "Detects AsyncRAT Telegram C2 Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R402.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R402",
            Name = "AsyncRAT Telegram C2 Pattern",
            Category = "MalwareC2",
            Description = "Detects AsyncRAT Telegram C2 Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Critical,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Tls, RuleTelemetryKind.Dns, RuleTelemetryKind.Ja3, RuleTelemetryKind.Ja4, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "destination_or_host", "c2_protocol_or_payload_marker" },
            EvidenceFields = new[] { "network.destination", "http.path", "tls.fingerprint", "matched_conditions" },
            PositiveConditions = new[] { "AsyncRAT Telegram C2 Pattern requires observable MalwareC2 telemetry and will not match descriptor text alone.", "Source and destination, host, process, protocol, path, port, or payload evidence must be present.", "The configured signal count and time-window threshold must be satisfied before a DetectionEvent is emitted." },
            NegativeConditions = new[] { "Do not match on product names, rule names, documentation text, or generic banners alone.", "Do not match when source/destination context is absent or when the traffic is inside an approved management path.", "Do not match known monitoring, backup, CI/CD, inventory, scanner, or administrative workflows unless rule-specific high-risk evidence remains." },
            FalsePositives = new[] { "Security testing frameworks, malware sandboxes, red-team infrastructure, and threat-intel replay traffic may look similar; mark approved test ranges explicitly." },
            TextIndicators = new[] { "asyncrat telegram c2 pattern", "async", "rat", "telegram", "beacon", "callback", "stager", "implant", "c2", "command and control" },
            HostIndicators = new[] { "api.telegram.org", "telegram.org" },
            PathIndicators = new[] { "/jquery", "/submit.php", "/gate.php", "/api/v1", "/news.php", "/login/process", "/payload", "/stage", "/callback" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = new[] { "http", "https", "tls", "dns" },
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 86,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(30),
            Cooldown = TimeSpan.FromMinutes(45),
            DistinctBy = "source+destination+malwarec2+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedRedTeamRanges", "ApprovedSandboxHosts", "BeaconWindowSeconds", "JitterThreshold" },
            RequiredTests = new[] { "positive R402 evidence-gated sample", "negative R402 descriptor-only sample", "negative R402 missing telemetry sample", "negative R402 approved-admin sample" },
            RequireOutboundExternal = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R402_AsyncRATTelegramC2PatternRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
            => EvaluateSpec(context, Spec);
    }
}
