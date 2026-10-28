// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R302_KubeletRunOrExecProbeRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R302_KubeletRunOrExecProbeRule : KubernetesContainerPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R302",
            Name: "Kubelet Run Or Exec Probe",
            Category: "KubernetesContainer",
            Description: "Detects Kubelet Run Or Exec Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R302.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R302",
            Name = "Kubelet Run Or Exec Probe",
            Category = "KubernetesContainer",
            Description = "Detects Kubelet Run Or Exec Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Critical,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination_or_host", "kubernetes_or_container_context" },
            EvidenceFields = new[] { "kubernetes.api.path", "network.source", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "Require authenticated service identity, operation outcome and relevant approved asset context from a trusted producer.", "Fail closed while these provenance contracts are unavailable." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Cluster administrators, CI/CD runners, and vulnerability scanners can legitimately query Kubernetes or registry APIs." },
            TextIndicators = new[] { "kubelet", "run", "exec", "/run/", "/exec/" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "/run/", "/exec/", "/cri/" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = new[] { "POST" },
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 10250, 10255 },
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
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R302_KubeletRunOrExecProbeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // This packet record does not carry authenticated service identity and operation outcomes.
            // Do not turn Info, a port number or a request path into an asserted security result.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "KUBELET_EXEC_REQUEST_PROVENANCE_UNAVAILABLE",
                "A run/exec path or POST does not prove a validated Kubelet endpoint, an authorized API operation, or a command-execution outcome.");
        }
    }
}
