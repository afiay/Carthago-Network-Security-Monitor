// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R372_DependencyConfusionPackageNamePatternRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R372_DependencyConfusionPackageNamePatternRule : DevOpsSupplyChainPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R372",
            Name: "Dependency Confusion Package Name Pattern",
            Category: "DevOpsSupplyChain",
            Description: "Detects Dependency Confusion Package Name Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R372.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R372",
            Name = "Dependency Confusion Package Name Pattern",
            Category = "DevOpsSupplyChain",
            Description = "Detects Dependency Confusion Package Name Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Medium,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.DevOpsAudit, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "destination_or_host", "devops_or_secret_context" },
            EvidenceFields = new[] { "devops.host", "http.path", "token.pattern", "matched_conditions" },
            PositiveConditions = new[] { "Dependency Confusion Package Name Pattern requires concrete DevOpsSupplyChain telemetry, not descriptor text.", "The source and destination or identity context must be present.", "At least two independent rule-specific signals must be present, or the rule-specific threshold must be met." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "CI/CD jobs, package mirrors, vulnerability scanners, and authorized secret-management automations can trigger these rules." },
            TextIndicators = new[] { "dependency confusion", "package name", "namespace", "typosquat", "internal package" },
            HostIndicators = new[] { "npmjs.com", "pypi.org", "rubygems.org", "nuget.org" },
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 74,
            WindowThreshold = 2,
            Window = TimeSpan.FromMinutes(30),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+devopssupplychain+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R372 evidence-gated sample", "negative R372 descriptor-only sample", "negative R372 missing telemetry sample" },
            RequireHttp = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R372_DependencyConfusionPackageNamePatternRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var rejection = CloudRequestPrecisionEvidence.Reject(context.Record, context.TimestampUtc, "R372");
            if (rejection != null)
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence, rejection,
                    "Rule-specific packet or authenticated audit evidence is unavailable.");
            return EvaluateSpec(context, Spec);
        }
    }
}
