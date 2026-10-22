// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/Packs/DevOpsPackProvider.cs
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Services.Benchmarking;
using Carthago.Services.Response;

namespace Carthago.Engine.ContentPacks.Packs
{
    internal sealed class DevOpsPackProvider : CompiledContentPackProviderBase
    {
        private static readonly IReadOnlyList<string> SourceRules = Concat(
            Range(204, 212),
            Range(353, 372),
            new[] { "R424" },
            Range(426, 432),
            new[] { "R440", "R447", "R448" }).ToArray();

        private readonly ContentPackManifest _manifest = new()
        {
            PackId = "carthago.devops.v1",
            Name = "DevOps / Supply Chain Pack",
            Version = "1.0.0",
            Description = "Optional DevOps and supply-chain pack for Jenkins, GitHub/GitLab, package repositories, CI runners, secrets managers, and automation abuse.",
            Category = "DevOpsSupplyChain",
            Author = "Carthago",
            MinimumCarthagoVersion = "1.0.0",
            Rules = AliasRules("DEVOPS", SourceRules, "DevOpsSupplyChain"),
            Profiles = Profiles(
                Profile("Enterprise", RuleMode.Alert, 0.76, "Enterprise can alert once CI/CD infrastructure is configured.", "Approved.CiCdServers"),
                Profile("SmallBusiness", RuleMode.Shadow, null, "Shadow by default for mixed DevOps and business workloads.", "Approved.CiCdServers"),
                Profile("HomeLab", RuleMode.Disabled, null, "Disabled until CI/CD and secret-manager assets are intentionally configured.", "Approved.CiCdServers"),
                Profile("Research", RuleMode.Alert, 0.60, "Research keeps supply-chain detections broad for validation.", "Approved.CiCdServers")
            ),
            RequiredTelemetry = new List<string> { "CI/CD web and API telemetry", "package repository visibility", "secret-manager and artifact-store traffic" },
            ReplaySamples = Samples(
                Sample("devops-jenkins-crumb", @"Tests/RuleReplaySamples/malicious/devops-jenkins-crumb.json", ReplaySampleClassification.Malicious, "Positive sample for Jenkins crumb issuer enumeration.", "DEVOPS013"),
                Sample("devops-benign-browsing", @"Tests/RuleReplaySamples/benign/normal-browsing.json", ReplaySampleClassification.Benign, "General browsing should not activate DevOps detections.")
            ),
            Benchmarks = BenchmarkExpectations(
                Benchmark("Enterprise", 0.70, 0),
                Benchmark("Research", 0.80, 1)
            ),
            HuntingQueries = Hunts(
                Hunt("devops-hunt-001", "Jenkins abuse", "Review Jenkins script-console and crumb-issuer probing.", "DEVOPS012", 0.65),
                Hunt("devops-hunt-002", "GitHub/GitLab API token misuse", "Find PAT, private-token, and clone/push anomalies.", "DEVOPS010", 0.70),
                Hunt("devops-hunt-003", "Package repository exfil", "Review suspicious npm, PyPI, Maven, and artifact-repository activity.", "DEVOPS017", 0.65),
                Hunt("devops-hunt-004", "Vault and secret-manager access", "Find secret-manager and Vault token anomalies.", "DEVOPS021", 0.70)
            ),
            ResponseRecommendations = Recommendations(
                Recommend("devops-response-001", "Rotate registry or CI token recommendation", "Recommend rotating the implicated registry or CI credential after owner review.", ResponseActionType.MarkForReview, ResponseActionSafety.ApprovalRequired, "Token rotation is sensitive and requires explicit pipeline-owner approval.", new[] { "DEVOPS010", "DEVOPS021", "DEVOPS024" }, "Identify the affected automation account.", "Rotate the token through the source system."),
                Recommend("devops-response-002", "Inspect runner and build logs", "Recommend collecting CI runner, build, and artifact access telemetry.", ResponseActionType.ExportEvidenceBundle, ResponseActionSafety.Informational, "Collection remains read-only by default.", new[] { "DEVOPS013", "DEVOPS019", "DEVOPS020" }, "Pull recent build logs.", "Correlate with detection journal evidence."),
                Recommend("devops-response-003", "Restrict package publish path", "Recommend restricting suspicious publish paths only after explicit review.", ResponseActionType.RecommendBlockDomain, ResponseActionSafety.RecommendationOnly, "Do not auto-block package repositories from content-pack defaults.", new[] { "DEVOPS017", "DEVOPS018" }, "Validate business ownership.", "Coordinate with the repository owner before blocking.")
            ),
            DashboardPresets = Presets(
                Preset("devops-dashboard-001", "Supply Chain & Secrets", "Surfaces CI token, secret-manager, and artifact anomalies.", "Enterprise", ("category", "DevOpsSupplyChain")),
                Preset("devops-dashboard-002", "Research Pipeline Replay", "Broad DevOps replay and hunt view.", "Research", ("packId", "carthago.devops.v1"))
            ),
            References = References(
                Ref("MITRE ATT&CK", "Compromise Infrastructure", "https://attack.mitre.org/techniques/T1584/", "T1584"),
                Ref("CISA", "Software supply chain security guidance", "https://www.cisa.gov/topics/cyber-threats-and-advisories/software-supply-chain-security"),
                Ref("Sigma", "DevOps and build-system detection guidance", "https://sigmahq.io/docs/")
            ),
            Changelog = new List<string> { "1.0.0 - Initial compiled DevOps and supply-chain pack release." },
            SafetyNotes = new List<string>
            {
                "Pack remains disabled when CI/CD servers are not configured.",
                "Recommendations never auto-revoke runner tokens or auto-block repositories."
            },
            License = "MIT"
        };

        public override ContentPackManifest Manifest => _manifest;
    }
}
