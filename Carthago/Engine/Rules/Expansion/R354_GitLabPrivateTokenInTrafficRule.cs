// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R354_GitLabPrivateTokenInTrafficRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R354_GitLabPrivateTokenInTrafficRule : DevOpsSupplyChainPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R354",
            Name: "GitLab Private Token In Traffic",
            Category: "DevOpsSupplyChain",
            Description: "Detects GitLab Private Token In Traffic only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R354.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R354",
            Name = "GitLab Private Token In Traffic",
            Category = "DevOpsSupplyChain",
            Description = "Detects GitLab Private Token In Traffic only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Critical,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.DevOpsAudit, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "destination_or_host", "devops_or_secret_context" },
            EvidenceFields = new[] { "devops.host", "http.path", "token.pattern", "matched_conditions" },
            PositiveConditions = new[] { "GitLab Private Token In Traffic requires concrete DevOpsSupplyChain telemetry, not descriptor text.", "The source and destination or identity context must be present.", "At least two independent rule-specific signals must be present, or the rule-specific threshold must be met." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "CI/CD jobs, package mirrors, vulnerability scanners, and authorized secret-management automations can trigger these rules." },
            TextIndicators = new[] { "gitlab", "private-token", "pat", "authorization" },
            HostIndicators = new[] { "gitlab.com" },
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = new[] { "gitlab" },
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+devopssupplychain+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R354 evidence-gated sample", "negative R354 descriptor-only sample", "negative R354 missing telemetry sample" },
            RequireHttp = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R354_GitLabPrivateTokenInTrafficRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            // Parser-owned token flags are only meaningful alongside an
            // attributed cleartext HTTP request. HTTPS/SNI, Info and generic
            // authorization vocabulary do not expose token bytes.
            if (!record.IsTcp || record.IsUdp
                || !string.Equals(record.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                || string.IsNullOrWhiteSpace(record.HttpMethod)
                || string.IsNullOrWhiteSpace(record.HttpUri))
                return NoMatch(RuleNoMatchReasonCategory.MissingTelemetry,
                    "CAPTURED_HTTP_REQUEST_NOT_ATTRIBUTED",
                    "A parser-attributed TCP HTTP request is required before token-pattern evaluation.");
            return EvaluateSpec(context, Spec);
        }
    }
}
