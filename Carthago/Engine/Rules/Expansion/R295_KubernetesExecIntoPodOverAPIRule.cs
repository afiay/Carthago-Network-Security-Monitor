// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R295_KubernetesExecIntoPodOverAPIRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R295_KubernetesExecIntoPodOverAPIRule : KubernetesContainerPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R295",
            Name: "Kubernetes Exec Into Pod Over API",
            Category: "KubernetesContainer",
            Description: "Detects Kubernetes Exec Into Pod Over API only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R295.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R295",
            Name = "Kubernetes Exec Into Pod Over API",
            Category = "KubernetesContainer",
            Description = "Detects Kubernetes Exec Into Pod Over API only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Critical,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination_or_host", "kubernetes_or_container_context" },
            EvidenceFields = new[] { "kubernetes.api.path", "network.source", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "Require validated exploit/protocol or authenticated API-audit evidence from a trusted producer.", "Fail closed until that evidence is available and reviewed." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Cluster administrators, CI/CD runners, and vulnerability scanners can legitimately query Kubernetes or registry APIs." },
            TextIndicators = new[] { "pods/exec", "exec into pod", "remotecommand", "kubectl exec" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "/exec", "/remotecommand" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = new[] { "POST" },
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 6443, 10250 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+kubernetescontainer+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "negative R295 apparent positive without trusted producer", "negative R295 spoofed/contradictory evidence", "negative R295 replay, privacy and profile invariants" },
            RequireHttp = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R295_KubernetesExecIntoPodOverAPIRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // Neither packet Info, ordinary endpoint paths, nor headers authenticate this outcome.
            // A trusted, reviewed producer must be integrated before this rule can match.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "K8S_POD_EXEC_AUDIT_UNAVAILABLE",
                "No trusted Kubernetes pod exec authorization, upgrade/session audit or validated API-server identity is available; a POST or upgrade header does not prove pod execution.");
        }
    }
}
