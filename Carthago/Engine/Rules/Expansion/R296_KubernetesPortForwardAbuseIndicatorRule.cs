// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R296_KubernetesPortForwardAbuseIndicatorRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R296_KubernetesPortForwardAbuseIndicatorRule : KubernetesContainerPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R296",
            Name: "Kubernetes PortForward Abuse Indicator",
            Category: "KubernetesContainer",
            Description: "Detects Kubernetes PortForward Abuse Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R296.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R296",
            Name = "Kubernetes PortForward Abuse Indicator",
            Category = "KubernetesContainer",
            Description = "Detects Kubernetes PortForward Abuse Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination_or_host", "kubernetes_or_container_context" },
            EvidenceFields = new[] { "kubernetes.api.path", "network.source", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "Require authenticated API, runtime or host-audit outcome from a trusted producer.", "Fail closed until validated provenance and approval context are available." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Cluster administrators, CI/CD runners, and vulnerability scanners can legitimately query Kubernetes or registry APIs." },
            TextIndicators = new[] { "portforward", "port-forward", "pods/portforward" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "/portforward" },
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
            RequiredTests = new[] { "negative R296 apparent positive without trusted producer", "negative R296 spoofed/contradictory evidence", "negative R296 replay, privacy and profile invariants" },
            RequireHttp = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R296_KubernetesPortForwardAbuseIndicatorRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // Network path/port labels and packet Info cannot authenticate this outcome.
            // Do not claim a runtime or Kubernetes operation without trusted producer evidence.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "K8S_PORT_FORWARD_AUDIT_UNAVAILABLE",
                "No authenticated Kubernetes port-forward upgrade/session audit, principal attribution or approved administrative-session context is connected; a POST path is not proof of abuse.");
        }
    }
}
