// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R311_CloudWorkloadMetadataTokenRequestRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R311_CloudWorkloadMetadataTokenRequestRule : KubernetesContainerPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R311",
            Name: "Cloud Workload Metadata Token Request",
            Category: "KubernetesContainer",
            Description: "Detects Cloud Workload Metadata Token Request only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R311.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R311",
            Name = "Cloud Workload Metadata Token Request",
            Category = "KubernetesContainer",
            Description = "Detects Cloud Workload Metadata Token Request only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Critical,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination_or_host", "kubernetes_or_container_context" },
            EvidenceFields = new[] { "kubernetes.api.path", "network.source", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "Require authenticated producer evidence and approved asset context before classifying the named behavior.", "Fail closed while the relevant identity, response, or outcome contracts are unavailable." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Cluster administrators, CI/CD runners, and vulnerability scanners can legitimately query Kubernetes or registry APIs." },
            TextIndicators = new[] { "metadata token", "imds", "169.254.169.254", "metadata.google.internal", "metadata/identity/oauth2/token" },
            HostIndicators = new[] { "169.254.169.254", "metadata.google.internal" },
            PathIndicators = new[] { "/latest/meta-data", "/computeMetadata", "/metadata/identity/oauth2/token" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+kubernetescontainer+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "negative apparent-positive without trusted producer", "negative spoofed and contradictory telemetry", "negative replay, privacy and profile invariants" },
            RequireHttp = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R311_CloudWorkloadMetadataTokenRequestRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // Packet metadata cannot authenticate the identity, policy or operation outcome required by this rule.
            // Avoid promoting labels, ports, URLs or Info strings to trusted security events.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "CLOUD_WORKLOAD_IDENTITY_AND_TOKEN_RESPONSE_UNAVAILABLE",
                "A metadata endpoint request does not establish a cloud workload identity, returned token or credential access. Require trusted workload inventory and token-response audit.");
        }
    }
}
