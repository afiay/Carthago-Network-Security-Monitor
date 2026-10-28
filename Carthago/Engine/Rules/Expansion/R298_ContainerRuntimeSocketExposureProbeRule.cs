// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R298_ContainerRuntimeSocketExposureProbeRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R298_ContainerRuntimeSocketExposureProbeRule : KubernetesContainerPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R298",
            Name: "Container Runtime Socket Exposure Probe",
            Category: "KubernetesContainer",
            Description: "Detects Container Runtime Socket Exposure Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R298.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R298",
            Name = "Container Runtime Socket Exposure Probe",
            Category = "KubernetesContainer",
            Description = "Detects Container Runtime Socket Exposure Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Critical,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination_or_host", "kubernetes_or_container_context" },
            EvidenceFields = new[] { "kubernetes.api.path", "network.source", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "Require authenticated API, runtime or host-audit outcome from a trusted producer.", "Fail closed until validated provenance and approval context are available." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Cluster administrators, CI/CD runners, and vulnerability scanners can legitimately query Kubernetes or registry APIs." },
            TextIndicators = new[] { "docker.sock", "containerd.sock", "crio.sock", "runtime socket", "/containers/json" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "/var/run/docker.sock", "/containers/json" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 2375, 2376 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+kubernetescontainer+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "negative R298 apparent positive without trusted producer", "negative R298 spoofed/contradictory evidence", "negative R298 replay, privacy and profile invariants" },
            RequireHttp = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R298_ContainerRuntimeSocketExposureProbeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // Network path/port labels and packet Info cannot authenticate this outcome.
            // Do not claim a runtime or Kubernetes operation without trusted producer evidence.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "RUNTIME_SOCKET_EXPOSURE_AUDIT_UNAVAILABLE",
                "No trusted host runtime-socket exposure inventory or validated Docker/containerd/CRI API endpoint identity is available; a TCP port or path does not prove Unix socket exposure.");
        }
    }
}
