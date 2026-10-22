// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/Packs/Microsoft365PackProvider.cs
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Services.Benchmarking;
using Carthago.Services.Response;

namespace Carthago.Engine.ContentPacks.Packs
{
    internal sealed class Microsoft365PackProvider : CompiledContentPackProviderBase
    {
        private static readonly IReadOnlyList<string> SourceRules = Concat(
            Range(129, 137),
            Range(154, 155),
            Range(273, 285),
            Range(317, 332)).ToArray();

        private readonly ContentPackManifest _manifest = new()
        {
            PackId = "carthago.microsoft365.v1",
            Name = "Microsoft 365 / Collaboration Pack",
            Version = "1.0.0",
            Description = "Optional Microsoft 365 and collaboration pack for OWA/EWS abuse, Teams/SharePoint/OneDrive anomalies, Graph export behavior, and device-code or consent abuse visible on the network.",
            Category = "Microsoft365",
            Author = "Carthago",
            MinimumCarthagoVersion = "1.0.0",
            Rules = AliasRules("M365", SourceRules, "Microsoft365"),
            Profiles = Profiles(
                Profile("Enterprise", RuleMode.Alert, 0.76, "Enterprise defaults promote higher-confidence M365 export and auth abuse findings to Alert."),
                Profile("SmallBusiness", RuleMode.Shadow, null, "Keep collaboration detections visible but non-paging until tenant-specific patterns are reviewed."),
                Profile("HomeLab", RuleMode.Shadow, null, "Shadow by default for personal tenants and labs."),
                Profile("Research", RuleMode.Alert, 0.60, "Research keeps broad collaboration coverage alerting for validation.")
            ),
            RequiredTelemetry = new List<string> { "HTTP/S collaboration telemetry", "M365 auth and Graph visibility", "mailbox and file-export indicators" },
            ReplaySamples = Samples(
                Sample("m365-device-code", @"Tests/RuleReplaySamples/malicious/oauth-device-code-phishing.json", ReplaySampleClassification.Malicious, "Positive sample for device-code abuse against Microsoft login infrastructure.", "M365014"),
                Sample("m365-benign-browsing", @"Tests/RuleReplaySamples/benign/normal-browsing.json", ReplaySampleClassification.Benign, "General web browsing should not activate M365 export detections.")
            ),
            Benchmarks = BenchmarkExpectations(
                Benchmark("Enterprise", 0.70, 0),
                Benchmark("Research", 0.80, 1)
            ),
            HuntingQueries = Hunts(
                Hunt("m365-hunt-001", "Exchange abuse", "Find OWA, EWS, and mailbox-export activity.", "M365025", 0.65),
                Hunt("m365-hunt-002", "Graph API export patterns", "Review Graph and API-export behavior from collaboration services.", "M365028", 0.65),
                Hunt("m365-hunt-003", "Suspicious webhook usage", "Find collaboration webhook callbacks and uploads.", "M365035", 0.60),
                Hunt("m365-hunt-004", "Unusual admin portal access", "Review suspicious cloud admin-console sign-ins.", "M365020", 0.70)
            ),
            ResponseRecommendations = Recommendations(
                Recommend("m365-response-001", "Review OAuth consent and device-code activity", "Recommend validating tenant consent records and recent device-code flows.", ResponseActionType.MarkForReview, ResponseActionSafety.RecommendationOnly, "Do not auto-revoke tenant-wide app permissions from content-pack defaults.", new[] { "M365014", "M365015" }, "Review app-consent records.", "Check whether the source account is expected."),
                Recommend("m365-response-002", "Check SaaS audit logs", "Recommend collecting Exchange, SharePoint, OneDrive, and Graph audit telemetry.", ResponseActionType.ExportEvidenceBundle, ResponseActionSafety.Informational, "Evidence collection should remain read-only by default.", new[] { "M365028", "M365036", "M365040" }, "Export the relevant audit timeline.", "Correlate with journaled DetectionEvent IDs."),
                Recommend("m365-response-003", "Reset credential recommendation", "Recommend resetting the implicated credential only after tenant-owner approval.", ResponseActionType.MarkForReview, ResponseActionSafety.ApprovalRequired, "Credential resets are operationally sensitive and require explicit approval.", new[] { "M365020", "M365021", "M365024" }, "Validate whether compromise is likely.", "Coordinate with the identity owner before reset.")
            ),
            DashboardPresets = Presets(
                Preset("m365-dashboard-001", "Collaboration Exports & Auth", "Surfaces mailbox, Graph, and file-export behaviors.", "Enterprise", ("category", "Microsoft365")),
                Preset("m365-dashboard-002", "Research SaaS Validation", "Broad collaboration replay and hunt view.", "Research", ("packId", "carthago.microsoft365.v1"))
            ),
            References = References(
                Ref("MITRE ATT&CK", "Exfiltration Over Web Service", "https://attack.mitre.org/techniques/T1567/", "T1567"),
                Ref("CISA", "Secure cloud business applications", "https://www.cisa.gov/resources-tools/resources/secure-cloud-business-applications-scuba-project"),
                Ref("Sigma", "Identity and cloud SaaS rule guidance", "https://sigmahq.io/docs/")
            ),
            Changelog = new List<string> { "1.0.0 - Initial compiled Microsoft 365 and collaboration pack release." },
            SafetyNotes = new List<string>
            {
                "Pack remains advisory-first for tenant-wide account or permission changes.",
                "No destructive tenant control changes are automatic."
            },
            License = "MIT"
        };

        public override ContentPackManifest Manifest => _manifest;
    }
}
