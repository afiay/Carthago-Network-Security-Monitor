// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/Packs/CloudSaasPackProvider.cs
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Services.Benchmarking;
using Carthago.Services.Response;

namespace Carthago.Engine.ContentPacks.Packs
{
    internal sealed class CloudSaasPackProvider : CompiledContentPackProviderBase
    {
        private static readonly IReadOnlyList<string> SourceRules = Concat(
            Range(109, 112),
            new[] { "R275" },
            Range(198, 222),
            Range(373, 392)).ToArray();

        private readonly ContentPackManifest _manifest = new()
        {
            PackId = "carthago.cloud-saas.v1",
            Name = "Cloud / SaaS Pack",
            Version = "1.0.0",
            Description = "Optional cloud and SaaS coverage for metadata abuse, storage exfiltration, webhook misuse, OAuth abuse, and cloud-tunnel behavior.",
            Category = "CloudSaaS",
            Author = "Carthago",
            MinimumCarthagoVersion = "1.0.0",
            Rules = AliasRules("CLOUD", SourceRules, "CloudSaaS"),
            Profiles = Profiles(
                Profile("Enterprise", RuleMode.Alert, 0.78, "Enterprise defaults promote higher-confidence cloud detections to Alert while leaving weaker matches in Shadow."),
                Profile("SmallBusiness", RuleMode.Shadow, null, "Shadow by default to avoid SaaS noise until tenant-specific tuning is reviewed."),
                Profile("HomeLab", RuleMode.Shadow, null, "Home labs keep cloud detections visible but non-paging."),
                Profile("Research", RuleMode.Alert, 0.60, "Research keeps broad cloud coverage alerting for validation.")
            ),
            TuningDefaults = Overrides(
                Override("CLOUD006", confidenceFloor: 0.80, notes: "AWS metadata retrieval should stay high-confidence before paging."),
                Override("CLOUD007", confidenceFloor: 0.80, notes: "GCP metadata retrieval should stay high-confidence before paging."),
                Override("CLOUD008", confidenceFloor: 0.80, notes: "Azure metadata retrieval should stay high-confidence before paging.")
            ),
            RequiredTelemetry = new List<string> { "HTTP metadata", "cloud host enrichment", "upload directionality", "SaaS API hostnames" },
            ReplaySamples = Samples(
                Sample("cloud-aws-metadata", @"Tests/RuleReplaySamples/malicious/ssrf-imds.json", ReplaySampleClassification.Malicious, "Positive sample for cloud metadata abuse.", "CLOUD006"),
                Sample("cloud-oauth-device-code", @"Tests/RuleReplaySamples/malicious/oauth-device-code-phishing.json", ReplaySampleClassification.Malicious, "Positive sample for device-code abuse.", "CLOUD005"),
                Sample("cloud-cloudflared", @"Tests/RuleReplaySamples/malicious/cloudflared-tunnel.json", ReplaySampleClassification.Malicious, "Positive sample for cloud tunnel use.", "CLOUD046"),
                Sample("cloud-approved-upload", @"Tests/RuleReplaySamples/benign/normal-cloud-upload-approved.json", ReplaySampleClassification.Benign, "Benign approved cloud upload should not page.")
            ),
            Benchmarks = BenchmarkExpectations(
                Benchmark("Enterprise", 0.70, 0),
                Benchmark("Research", 0.80, 1)
            ),
            HuntingQueries = Hunts(
                Hunt("cloud-hunt-001", "Cloud metadata probes", "Find metadata-service retrieval and token requests.", "CLOUD006", 0.70),
                Hunt("cloud-hunt-002", "SaaS webhook uploads", "Find webhook-style upload patterns and collaboration API egress.", "CLOUD020", 0.60),
                Hunt("cloud-hunt-003", "First-time cloud provider by host", "Review novel cloud-provider contact from internal hosts.", "CLOUD027", 0.55),
                Hunt("cloud-hunt-004", "High upload ratio to personal cloud", "Find disproportionate upload traffic to cloud and personal-storage endpoints.", "CLOUD018", 0.65)
            ),
            ResponseRecommendations = Recommendations(
                Recommend("cloud-response-001", "Review OAuth app consent", "Review whether the observed OAuth/device-code activity maps to approved applications.", ResponseActionType.MarkForReview, ResponseActionSafety.RecommendationOnly, "Never revoke production tokens blindly without verifying tenant impact.", new[] { "CLOUD005" }, "Review application consent records.", "Compare the source host and account with SaaS audit telemetry."),
                Recommend("cloud-response-002", "Rotate exposed token", "Recommend rotating the affected API token or service credential after evidence review.", ResponseActionType.RecommendDisableNoisyRule, ResponseActionSafety.ApprovalRequired, "Credential rotation is operationally sensitive and requires explicit approval.", new[] { "CLOUD006", "CLOUD007", "CLOUD008" }, "Confirm the token was genuinely exposed.", "Rotate the token in the cloud control plane."),
                Recommend("cloud-response-003", "Block suspicious webhook URL", "Recommend blocking the suspicious webhook endpoint after validating business ownership.", ResponseActionType.RecommendBlockDomain, ResponseActionSafety.RecommendationOnly, "Do not auto-block webhook destinations from content packs.", new[] { "CLOUD020", "CLOUD021", "CLOUD022" }, "Validate destination ownership.", "Coordinate with SaaS owners before blocking.")
            ),
            DashboardPresets = Presets(
                Preset("cloud-dashboard-001", "Cloud Token & Metadata Risks", "Highlights metadata abuse, token access, and cloud tunnel findings.", "Enterprise", ("category", "CloudSaaS"), ("minimumConfidence", "0.70")),
                Preset("cloud-dashboard-002", "Research Cloud Expansion", "Broad cloud-focused preset for validation and replay review.", "Research", ("packId", "carthago.cloud-saas.v1"))
            ),
            References = References(
                Ref("MITRE ATT&CK", "Cloud Account Discovery", "https://attack.mitre.org/techniques/T1087/004/", "T1087.004"),
                Ref("CISA", "Cloud security technical reference architecture", "https://www.cisa.gov/resources-tools/resources/cloud-security-technical-reference-architecture"),
                Ref("Sigma", "Detection-as-content patterns", "https://sigmahq.io/docs/basics/rules.html")
            ),
            Changelog = new List<string> { "1.0.0 - Initial compiled cloud and SaaS content pack release." },
            SafetyNotes = new List<string>
            {
                "Pack remains disabled when required cloud/SaaS telemetry is absent.",
                "Never auto-revoke tokens or auto-block SaaS destinations from content-pack defaults."
            },
            License = "MIT"
        };

        public override ContentPackManifest Manifest => _manifest;
    }
}
