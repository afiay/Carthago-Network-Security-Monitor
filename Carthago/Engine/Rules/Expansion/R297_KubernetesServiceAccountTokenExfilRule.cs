// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R297_KubernetesServiceAccountTokenExfilRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R297_KubernetesServiceAccountTokenExfilRule : KubernetesContainerPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R297",
            Name: "Kubernetes ServiceAccount Token Exfil",
            Category: "KubernetesContainer",
            Description: "Detects Kubernetes ServiceAccount Token Exfil only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R297.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R297",
            Name = "Kubernetes ServiceAccount Token Exfil",
            Category = "KubernetesContainer",
            Description = "Detects Kubernetes ServiceAccount Token Exfil only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Critical,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination_or_host", "kubernetes_or_container_context" },
            EvidenceFields = new[] { "kubernetes.api.path", "network.source", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "Require authenticated API, runtime or host-audit outcome from a trusted producer.", "Fail closed until validated provenance and approval context are available." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Cluster administrators, CI/CD runners, and vulnerability scanners can legitimately query Kubernetes or registry APIs." },
            TextIndicators = new[] { "serviceaccount token", "service-account-token", "/var/run/secrets", "token exfil", "jwt" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "/var/run/secrets", "/secrets" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = new[] { "generic" },
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+kubernetescontainer+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "negative R297 apparent positive without trusted producer", "negative R297 spoofed/contradictory evidence", "negative R297 replay, privacy and profile invariants" },

        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R297_KubernetesServiceAccountTokenExfilRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // Network path/port labels and packet Info cannot authenticate this outcome.
            // Do not claim a runtime or Kubernetes operation without trusted producer evidence.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "K8S_TOKEN_EXFIL_PROVENANCE_UNAVAILABLE",
                "No trusted service-account token-read audit correlated to an independently verified external delivery event is available; a token path, TokenRequest or bearer header cannot prove exfiltration.");
        }
    }
}
