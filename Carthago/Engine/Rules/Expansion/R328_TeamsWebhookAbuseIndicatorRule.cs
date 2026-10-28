// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R328_TeamsWebhookAbuseIndicatorRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R328_TeamsWebhookAbuseIndicatorRule : EmailCollaborationPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R328",
            Name: "Teams Webhook Abuse Indicator",
            Category: "EmailCollaboration",
            Description: "Detects Teams Webhook Abuse Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R328.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R328",
            Name = "Teams Webhook Abuse Indicator",
            Category = "EmailCollaboration",
            Description = "Detects Teams Webhook Abuse Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Dns },
            RequiredFields = new[] { "source", "destination_or_host", "mail_or_collaboration_context" },
            EvidenceFields = new[] { "mail.protocol", "http.path", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "Teams Webhook Abuse Indicator requires concrete EmailCollaboration telemetry, not descriptor text.", "The source and destination or identity context must be present.", "At least two independent rule-specific signals must be present, or the rule-specific threshold must be met." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Mail migrations, eDiscovery exports, DLP tooling, and sanctioned collaboration automations can match these patterns." },
            TextIndicators = new[] { "teams webhook", "office webhook", "incoming webhook", "connector" },
            HostIndicators = new[] { "webhook.office.com", "office.com", "teams.microsoft.com" },
            PathIndicators = new[] { "/webhook", "/IncomingWebhook" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = new[] { "POST" },
            TokenKinds = Array.Empty<string>(),
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+emailcollaboration+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R328 evidence-gated sample", "negative R328 descriptor-only sample", "negative R328 missing telemetry sample" },
            RequireHttp = true,
            RequireOutboundExternal = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R328_TeamsWebhookAbuseIndicatorRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "TEAMS_WEBHOOK_AUDIT_UNAVAILABLE",
                "Webhook POST paths do not prove accepted messages or unauthorized activity. Require trusted connector audit.");
        }
    }
}
