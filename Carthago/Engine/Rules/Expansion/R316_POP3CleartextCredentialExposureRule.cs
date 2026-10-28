// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R316_POP3CleartextCredentialExposureRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R316_POP3CleartextCredentialExposureRule : EmailCollaborationPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R316",
            Name: "POP3 Cleartext Credential Exposure",
            Category: "EmailCollaboration",
            Description: "Detects POP3 Cleartext Credential Exposure only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R316.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R316",
            Name = "POP3 Cleartext Credential Exposure",
            Category = "EmailCollaboration",
            Description = "Detects POP3 Cleartext Credential Exposure only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Dns },
            RequiredFields = new[] { "source", "destination_or_host", "mail_or_collaboration_context" },
            EvidenceFields = new[] { "mail.protocol", "http.path", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "Require authenticated producer evidence and approved endpoint or identity context before classifying the named behavior.", "Fail closed while the relevant payload, response or outcome contracts are unavailable." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Mail migrations, eDiscovery exports, DLP tooling, and sanctioned collaboration automations can match these patterns." },
            TextIndicators = new[] { "pop3", "USER ", "PASS ", "cleartext", "password" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = new[] { "pop3" },
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 110 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+emailcollaboration+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "negative apparent-positive without trusted producer", "negative spoofed and contradictory telemetry", "negative replay, privacy and profile invariants" },
            RequireCleartext = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R316_POP3CleartextCredentialExposureRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // Ports, paths and Info text are not authenticated mail-operation or credential evidence.
            // Reject unsupported outcomes until a trusted, privacy-safe producer is integrated.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "POP3_CREDENTIAL_PAYLOAD_PARSER_UNAVAILABLE",
                "TCP/110, POP3 labels and USER/PASS strings in descriptions do not establish captured credential payload bytes or whether the session was protected. Require a bounded cleartext POP3 parser with redacted evidence.");
        }
    }
}
