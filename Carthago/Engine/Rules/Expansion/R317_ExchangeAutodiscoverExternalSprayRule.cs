// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R317_ExchangeAutodiscoverExternalSprayRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R317_ExchangeAutodiscoverExternalSprayRule : EmailCollaborationPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R317",
            Name: "Exchange Autodiscover External Spray",
            Category: "EmailCollaboration",
            Description: "Detects Exchange Autodiscover External Spray only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R317.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R317",
            Name = "Exchange Autodiscover External Spray",
            Category = "EmailCollaboration",
            Description = "Detects Exchange Autodiscover External Spray only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Medium,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Dns },
            RequiredFields = new[] { "source", "destination_or_host", "mail_or_collaboration_context" },
            EvidenceFields = new[] { "mail.protocol", "http.path", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "Require authenticated producer evidence and approved endpoint or identity context before classifying the named behavior.", "Fail closed while the relevant payload, response or outcome contracts are unavailable." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Mail migrations, eDiscovery exports, DLP tooling, and sanctioned collaboration automations can match these patterns." },
            TextIndicators = new[] { "autodiscover", "/autodiscover/autodiscover.xml", "exchange", "spray" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "/autodiscover/autodiscover.xml", "/autodiscover/" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 443, 80 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 74,
            WindowThreshold = 5,
            Window = TimeSpan.FromMinutes(15),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+emailcollaboration+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "negative apparent-positive without trusted producer", "negative spoofed and contradictory telemetry", "negative replay, privacy and profile invariants" },
            RequireHttp = true,
            RequireInboundExternal = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R317_ExchangeAutodiscoverExternalSprayRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // Ports, paths and Info text are not authenticated mail-operation or credential evidence.
            // Reject unsupported outcomes until a trusted, privacy-safe producer is integrated.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "AUTODISCOVER_ENDPOINT_AND_AUTH_AUDIT_UNAVAILABLE",
                "External HTTP requests to Autodiscover-like paths do not prove a verified Exchange endpoint, credential spray, failed logins or distinct accounts. Require trusted endpoint identity and authenticated outcomes.");
        }
    }
}
