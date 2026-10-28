// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R331_CalendarInvitePhishingLinkPatternRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R331_CalendarInvitePhishingLinkPatternRule : EmailCollaborationPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R331",
            Name: "Calendar Invite Phishing Link Pattern",
            Category: "EmailCollaboration",
            Description: "Candidate R331 requires authenticated operation and outcome provenance; packet-only indicators cannot establish the named behavior.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R331.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R331",
            Name = "Calendar Invite Phishing Link Pattern",
            Category = "EmailCollaboration",
            Description = "Candidate R331 requires authenticated operation and outcome provenance; packet-only indicators cannot establish the named behavior.",
            Severity = SeverityLevel.Medium,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Dns },
            RequiredFields = new[] { "source", "destination_or_host", "mail_or_collaboration_context" },
            EvidenceFields = new[] { "mail.protocol", "http.path", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "Calendar Invite Phishing Link Pattern requires concrete EmailCollaboration telemetry, not descriptor text.", "The source and destination or identity context must be present.", "At least two independent rule-specific signals must be present, or the rule-specific threshold must be met." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Mail migrations, eDiscovery exports, DLP tooling, and sanctioned collaboration automations can match these patterns." },
            TextIndicators = new[] { "calendar invite", "ics", "phishing", "meeting link", "href" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { ".ics", "/calendar", "/owa/calendar" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 74,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+emailcollaboration+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R331 evidence-gated sample", "negative R331 descriptor-only sample", "negative R331 missing telemetry sample" },
            RequireHttp = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R331_CalendarInvitePhishingLinkPatternRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // No authenticated application/session outcome producer is connected to this capture path.
            // Packet descriptions, paths and ports are not sufficient proof of this behavior.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "CALENDAR_INVITE_AUDIT_UNAVAILABLE",
                "A calendar URL or ICS-looking request does not prove an invitation was delivered or that its link is phishing. Require authenticated calendar message, recipient and validated destination evidence.");
        }
    }
}
