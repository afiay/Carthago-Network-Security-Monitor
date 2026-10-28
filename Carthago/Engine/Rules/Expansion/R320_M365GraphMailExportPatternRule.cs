// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R320_M365GraphMailExportPatternRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R320_M365GraphMailExportPatternRule : EmailCollaborationPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R320",
            Name: "M365 Graph Mail Export Pattern",
            Category: "EmailCollaboration",
            Description: "Detects M365 Graph Mail Export Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R320.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R320",
            Name = "M365 Graph Mail Export Pattern",
            Category = "EmailCollaboration",
            Description = "Detects M365 Graph Mail Export Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Dns },
            RequiredFields = new[] { "source", "destination_or_host", "mail_or_collaboration_context" },
            EvidenceFields = new[] { "mail.protocol", "http.path", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "Require authenticated producer evidence and approved endpoint or identity context before classifying the named behavior.", "Fail closed while the relevant payload, response or outcome contracts are unavailable." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Mail migrations, eDiscovery exports, DLP tooling, and sanctioned collaboration automations can match these patterns." },
            TextIndicators = new[] { "graph", "mailfolders", "messages", "export", "download", "delta" },
            HostIndicators = new[] { "graph.microsoft.com" },
            PathIndicators = new[] { "/v1.0/me/messages", "/users/", "/messages", "/mailFolders" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 5,
            Window = TimeSpan.FromMinutes(30),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+emailcollaboration+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "negative apparent-positive without trusted producer", "negative spoofed and contradictory telemetry", "negative replay, privacy and profile invariants" },
            RequireHttp = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R320_M365GraphMailExportPatternRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // Ports, paths and Info text are not authenticated mail-operation or credential evidence.
            // Reject unsupported outcomes until a trusted, privacy-safe producer is integrated.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "GRAPH_MAIL_EXPORT_AUDIT_UNAVAILABLE",
                "Graph hostnames, message URLs and declared bytes do not prove authenticated Graph mail export or delivered mailbox contents. Require Microsoft Graph operation audit and authorized identity/transfer evidence.");
        }
    }
}
