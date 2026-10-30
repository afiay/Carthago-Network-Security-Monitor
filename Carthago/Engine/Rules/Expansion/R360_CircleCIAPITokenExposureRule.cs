// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R360_CircleCIAPITokenExposureRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R360_CircleCIAPITokenExposureRule : DevOpsSupplyChainPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R360",
            Name: "CircleCI API Token Exposure",
            Category: "DevOpsSupplyChain",
            Description: "Detects CircleCI API Token Exposure only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R360.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R360",
            Name = "CircleCI API Token Exposure",
            Category = "DevOpsSupplyChain",
            Description = "Detects CircleCI API Token Exposure only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.DevOpsAudit, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "destination_or_host", "devops_or_secret_context" },
            EvidenceFields = new[] { "devops.host", "http.path", "token.pattern", "matched_conditions" },
            PositiveConditions = new[] { "CircleCI API Token Exposure requires concrete DevOpsSupplyChain telemetry, not descriptor text.", "The source and destination or identity context must be present.", "At least two independent rule-specific signals must be present, or the rule-specific threshold must be met." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "CI/CD jobs, package mirrors, vulnerability scanners, and authorized secret-management automations can trigger these rules." },
            TextIndicators = new[] { "circleci", "circle-token", "api token" },
            HostIndicators = new[] { "circleci.com" },
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = new[] { "circleci", "generic" },
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+devopssupplychain+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R360 evidence-gated sample", "negative R360 descriptor-only sample", "negative R360 missing telemetry sample" },
            RequireHttp = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R360_CircleCIAPITokenExposureRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!DevOpsHttpEvidence.HasParsedRequest(r))
                return NoMatch(RuleNoMatchReasonCategory.MissingTelemetry, "CIRCLECI_HTTP_REQUEST_MISSING", "Parsed TCP/HTTP request required.");
            if (DevOpsHttpEvidence.OriginPath(r.HttpUri) == null)
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence, "CIRCLECI_TARGET_UNTRUSTED", "Origin-form request target required.");
            if (!DevOpsHttpEvidence.HostMatches(r, "circleci.com", subdomains: true))
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence, "CIRCLECI_HOST_NOT_OBSERVED", "CircleCI HTTP Host required.");
            if (!r.HttpCircleCiTokenPatternObserved)
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence, "CIRCLECI_TOKEN_PARSER_FLAG_NOT_OBSERVED", "Complete Circle-Token header with token-shaped value required.");
            return EvaluateSpec(context, Spec);
        }
    }
}
