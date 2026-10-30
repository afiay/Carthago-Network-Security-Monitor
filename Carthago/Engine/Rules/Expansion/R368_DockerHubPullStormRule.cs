// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R368_DockerHubPullStormRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R368_DockerHubPullStormRule : DevOpsSupplyChainPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R368",
            Name: "Docker Hub Pull Storm",
            Category: "DevOpsSupplyChain",
            Description: "Detects Docker Hub Pull Storm only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R368.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R368",
            Name = "Docker Hub Pull Storm",
            Category = "DevOpsSupplyChain",
            Description = "Detects Docker Hub Pull Storm only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Medium,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.DevOpsAudit, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "destination_or_host", "devops_or_secret_context" },
            EvidenceFields = new[] { "devops.host", "http.path", "token.pattern", "matched_conditions" },
            PositiveConditions = new[] { "Docker Hub Pull Storm requires concrete DevOpsSupplyChain telemetry, not descriptor text.", "The source and destination or identity context must be present.", "At least two independent rule-specific signals must be present, or the rule-specific threshold must be met." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "CI/CD jobs, package mirrors, vulnerability scanners, and authorized secret-management automations can trigger these rules." },
            TextIndicators = new[] { "dockerhub", "docker hub", "pull storm", "manifests", "blobs" },
            HostIndicators = new[] { "docker.io", "registry-1.docker.io" },
            PathIndicators = new[] { "/v2/", "/manifests", "/blobs" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 74,
            WindowThreshold = 10,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+devopssupplychain+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R368 evidence-gated sample", "negative R368 descriptor-only sample", "negative R368 missing telemetry sample" },
            RequireHttp = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R368_DockerHubPullStormRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var rejection = DevOpsRequestPrecisionEvidence.Reject(context.Record, context.TimestampUtc, "R368");
            if (rejection != null)
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence, rejection, "Rule-specific parser-attributed request evidence is unavailable.");
            return EvaluateSpec(context, Spec);
        }
    }
}
