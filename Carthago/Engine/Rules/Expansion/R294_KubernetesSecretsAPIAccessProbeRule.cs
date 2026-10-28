// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R294_KubernetesSecretsAPIAccessProbeRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R294_KubernetesSecretsAPIAccessProbeRule : KubernetesContainerPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R294",
            Name: "Kubernetes Secrets API Access Probe",
            Category: "KubernetesContainer",
            Description: "Detects Kubernetes Secrets API Access Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R294.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R294",
            Name = "Kubernetes Secrets API Access Probe",
            Category = "KubernetesContainer",
            Description = "Detects Kubernetes Secrets API Access Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Critical,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination_or_host", "kubernetes_or_container_context" },
            EvidenceFields = new[] { "kubernetes.api.path", "network.source", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "Require validated exploit/protocol or authenticated API-audit evidence from a trusted producer.", "Fail closed until that evidence is available and reviewed." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Cluster administrators, CI/CD runners, and vulnerability scanners can legitimately query Kubernetes or registry APIs." },
            TextIndicators = new[] { "kubernetes", "secrets", "/secrets", "serviceaccount" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "/api/v1/secrets", "/secrets" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 6443, 8080 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+kubernetescontainer+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "negative R294 apparent positive without trusted producer", "negative R294 spoofed/contradictory evidence", "negative R294 replay, privacy and profile invariants" },
            RequireHttp = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R294_KubernetesSecretsAPIAccessProbeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // Neither packet Info, ordinary endpoint paths, nor headers authenticate this outcome.
            // A trusted, reviewed producer must be integrated before this rule can match.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "K8S_SECRETS_ACCESS_AUDIT_UNAVAILABLE",
                "No authenticated Kubernetes API secrets-access audit outcome or verified API-server identity is connected; a URI containing secrets cannot establish successful or unauthorized access.");
        }
    }
}
