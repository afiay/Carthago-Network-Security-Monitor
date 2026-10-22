// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/Packs/KubernetesPackProvider.cs
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Services.Benchmarking;
using Carthago.Services.Response;

namespace Carthago.Engine.ContentPacks.Packs
{
    internal sealed class KubernetesPackProvider : CompiledContentPackProviderBase
    {
        private static readonly IReadOnlyList<string> SourceRules = Concat(
            Range(160, 163),
            new[] { "R166" },
            Range(201, 203),
            Range(213, 216),
            Range(221, 222),
            Range(293, 312),
            new[] { "R368" },
            Range(387, 391)).ToArray();

        private readonly ContentPackManifest _manifest = new()
        {
            PackId = "carthago.kubernetes.v1",
            Name = "Kubernetes / Container Pack",
            Version = "1.0.0",
            Description = "Optional Kubernetes and container pack for API enumeration, pod exec, token access, registry abuse, metadata access, and cluster tunnels.",
            Category = "KubernetesContainer",
            Author = "Carthago",
            MinimumCarthagoVersion = "1.0.0",
            Rules = AliasRules("K8S", SourceRules, "KubernetesContainer"),
            Profiles = Profiles(
                Profile("Enterprise", RuleMode.Alert, 0.75, "Enterprise can alert once Kubernetes API servers are configured.", "Approved.KubernetesApiServers"),
                Profile("HomeLab", RuleMode.Disabled, null, "Disabled until Kubernetes APIs and namespaces are intentionally configured.", "Approved.KubernetesApiServers"),
                Profile("Research", RuleMode.Alert, 0.60, "Research keeps cluster activity alerting broad for replay validation.", "Approved.KubernetesApiServers")
            ),
            RequiredTelemetry = new List<string> { "Kubernetes API visibility", "container registry traffic", "service-account and metadata access telemetry" },
            ReplaySamples = Samples(
                Sample("k8s-pod-exec", @"Tests/RuleReplaySamples/malicious/kubernetes-pod-exec.json", ReplaySampleClassification.Malicious, "Positive sample for pod exec over the Kubernetes API.", "K8S017"),
                Sample("k8s-benign-browsing", @"Tests/RuleReplaySamples/benign/normal-browsing.json", ReplaySampleClassification.Benign, "General benign browsing should not activate container detections.")
            ),
            Benchmarks = BenchmarkExpectations(
                Benchmark("Enterprise", 0.70, 0),
                Benchmark("Research", 0.80, 1)
            ),
            HuntingQueries = Hunts(
                Hunt("k8s-hunt-001", "Pod exec", "Review exec, run, and interactive workload access.", "K8S017", 0.70),
                Hunt("k8s-hunt-002", "Kubelet unauthenticated access", "Find kubelet read-only and exec probes.", "K8S024", 0.65),
                Hunt("k8s-hunt-003", "Service-account token access", "Find Kubernetes service-account token access and exfil patterns.", "K8S006", 0.70),
                Hunt("k8s-hunt-004", "Registry push/pull anomaly", "Review suspicious image pulls and registry push behavior.", "K8S007", 0.60)
            ),
            ResponseRecommendations = Recommendations(
                Recommend("k8s-response-001", "Revoke service-account token recommendation", "Recommend revoking or rotating the implicated service-account token after cluster-owner review.", ResponseActionType.MarkForReview, ResponseActionSafety.ApprovalRequired, "Service-account actions require explicit cluster-owner approval.", new[] { "K8S006", "K8S019" }, "Identify the implicated namespace and workload.", "Rotate the token through the cluster control plane."),
                Recommend("k8s-response-002", "Inspect pod exec logs", "Recommend collecting Kubernetes audit and pod-exec traces.", ResponseActionType.ExportEvidenceBundle, ResponseActionSafety.Informational, "Evidence collection remains read-only by default.", new[] { "K8S017", "K8S018" }, "Pull API-server audit records.", "Correlate with pack EventIds."),
                Recommend("k8s-response-003", "Cordon node recommendation", "Recommend cordoning the affected node only after explicit approval.", ResponseActionType.RecommendIsolateHost, ResponseActionSafety.RecommendationOnly, "Do not auto-cordon nodes from content-pack defaults.", new[] { "K8S020", "K8S034" }, "Validate node criticality.", "Coordinate with platform operations before cordoning.")
            ),
            DashboardPresets = Presets(
                Preset("k8s-dashboard-001", "Cluster API Abuse", "Highlights API enumeration, kubelet, and exec behavior.", "Enterprise", ("category", "KubernetesContainer")),
                Preset("k8s-dashboard-002", "Research Container Expansion", "Broad cluster tuning view for replay and hunt work.", "Research", ("packId", "carthago.kubernetes.v1"))
            ),
            References = References(
                Ref("MITRE ATT&CK", "Escape to Host", "https://attack.mitre.org/techniques/T1611/", "T1611"),
                Ref("MITRE ATT&CK", "Steal Application Access Token", "https://attack.mitre.org/techniques/T1528/", "T1528"),
                Ref("CISA", "Kubernetes hardening guidance", "https://www.cisa.gov/resources-tools/resources/kubernetes-hardening-guidance")
            ),
            Changelog = new List<string> { "1.0.0 - Initial compiled Kubernetes and container pack release." },
            SafetyNotes = new List<string>
            {
                "Pack stays disabled when Kubernetes API server context is missing.",
                "Recommendations never auto-cordon nodes or auto-revoke cluster credentials."
            },
            License = "MIT"
        };

        public override ContentPackManifest Manifest => _manifest;
    }
}
