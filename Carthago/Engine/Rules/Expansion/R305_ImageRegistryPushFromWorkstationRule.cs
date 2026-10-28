// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R305_ImageRegistryPushFromWorkstationRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R305_ImageRegistryPushFromWorkstationRule : KubernetesContainerPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R305",
            Name: "Image Registry Push From Workstation",
            Category: "KubernetesContainer",
            Description: "Detects Image Registry Push From Workstation only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R305.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R305",
            Name = "Image Registry Push From Workstation",
            Category = "KubernetesContainer",
            Description = "Detects Image Registry Push From Workstation only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination_or_host", "kubernetes_or_container_context" },
            EvidenceFields = new[] { "kubernetes.api.path", "network.source", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "Require authenticated service identity, operation outcome and relevant approved asset context from a trusted producer.", "Fail closed while these provenance contracts are unavailable." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Cluster administrators, CI/CD runners, and vulnerability scanners can legitimately query Kubernetes or registry APIs." },
            TextIndicators = new[] { "registry push", "image push", "PUT", "PATCH", "upload" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "/v2/", "/blobs/uploads", "/manifests/" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = new[] { "PUT", "PATCH", "POST" },
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
            RequiredTests = new[] { "negative apparent positive without trusted producer", "negative spoofed and contradictory telemetry", "negative replay, privacy and profile invariants" },
            RequireHttp = true,
            RequireOutboundExternal = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R305_ImageRegistryPushFromWorkstationRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // This packet record does not carry authenticated service identity and operation outcomes.
            // Do not turn Info, a port number or a request path into an asserted security result.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "REGISTRY_PUSH_ASSET_AND_RESULT_UNAVAILABLE",
                "PUT/PATCH/POST to a registry path does not prove an accepted image push or that the source is an unapproved workstation.");
        }
    }
}
