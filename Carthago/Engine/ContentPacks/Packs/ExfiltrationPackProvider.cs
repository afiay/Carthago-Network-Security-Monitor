// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/Packs/ExfiltrationPackProvider.cs
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Services.Benchmarking;
using Carthago.Services.Response;

namespace Carthago.Engine.ContentPacks.Packs
{
    internal sealed class ExfiltrationPackProvider : CompiledContentPackProviderBase
    {
        private static readonly IReadOnlyList<string> SourceRules = Concat(
            Range(104, 108),
            Range(243, 257),
            Range(493, 512)).ToArray();

        private readonly ContentPackManifest _manifest = new()
        {
            PackId = "carthago.exfiltration.v1",
            Name = "Exfiltration Pack",
            Version = "1.0.0",
            Description = "Optional exfiltration pack for archive staging, dump transfers, cloud upload bursts, split exfiltration, rclone-style tools, and post-sweep encrypted uploads.",
            Category = "Exfiltration",
            Author = "Carthago",
            MinimumCarthagoVersion = "1.0.0",
            Rules = AliasRules("EXFIL", SourceRules, "Exfiltration"),
            Profiles = Profiles(
                Profile("Enterprise", RuleMode.Alert, 0.78, "Enterprise promotes higher-confidence exfiltration signals to Alert."),
                Profile("SmallBusiness", RuleMode.Shadow, null, "Shadow by default until approved destinations and transfer workflows are tuned."),
                Profile("HomeLab", RuleMode.Shadow, null, "Home labs keep exfiltration heuristics visible but non-paging."),
                Profile("Research", RuleMode.Alert, 0.60, "Research alerts broadly for exfiltration replay coverage.")
            ),
            RequiredTelemetry = new List<string> { "upload ratio and byte counts", "HTTP/S upload telemetry", "archive and sensitive-file indicators" },
            ReplaySamples = Samples(
                Sample("exfil-rclone", @"Tests/RuleReplaySamples/malicious/rclone-exfil.json", ReplaySampleClassification.Malicious, "Positive sample for rclone-like exfiltration.", "EXFIL036"),
                Sample("exfil-approved-upload", @"Tests/RuleReplaySamples/benign/normal-cloud-upload-approved.json", ReplaySampleClassification.Benign, "Approved cloud upload should stay non-critical.")
            ),
            Benchmarks = BenchmarkExpectations(
                Benchmark("Enterprise", 0.75, 0),
                Benchmark("Research", 0.85, 1)
            ),
            HuntingQueries = Hunts(
                Hunt("exfil-hunt-001", "Archive staging", "Review archive and dump staging before outbound transfer.", "EXFIL006", 0.65),
                Hunt("exfil-hunt-002", "Cloud storage upload burst", "Find burst uploads to cloud storage or personal repositories.", "EXFIL004", 0.60),
                Hunt("exfil-hunt-003", "Low-and-slow exfil", "Review repeated small uploads and unusual ratios.", "EXFIL012", 0.60),
                Hunt("exfil-hunt-004", "CLI exfil indicators", "Find rclone, mega, rsync, and related upload tooling.", "EXFIL036", 0.70)
            ),
            ResponseRecommendations = Recommendations(
                Recommend("exfil-response-001", "Preserve evidence bundle", "Recommend preserving packet, archive, and process evidence before containment.", ResponseActionType.ExportEvidenceBundle, ResponseActionSafety.Informational, "Evidence collection remains non-destructive by default.", new[] { "EXFIL006", "EXFIL020", "EXFIL036" }, "Preserve the network trace.", "Correlate with any source-host collection telemetry."),
                Recommend("exfil-response-002", "Isolate host recommendation", "Recommend isolating the suspected host after evidence review.", ResponseActionType.RecommendIsolateHost, ResponseActionSafety.RecommendationOnly, "Do not auto-isolate hosts from exfiltration pack defaults.", new[] { "EXFIL006", "EXFIL018", "EXFIL036" }, "Validate business impact.", "Capture evidence before isolation."),
                Recommend("exfil-response-003", "Block destination recommendation", "Recommend blocking the suspicious upload destination only after validation.", ResponseActionType.RecommendBlockDomain, ResponseActionSafety.RecommendationOnly, "Never auto-block on a content-pack recommendation alone.", new[] { "EXFIL004", "EXFIL036", "EXFIL040" }, "Validate destination ownership.", "Coordinate with network operations before blocking.")
            ),
            DashboardPresets = Presets(
                Preset("exfil-dashboard-001", "Uploads & Staging", "Highlights archive staging, split exfiltration, and cloud uploads.", "Enterprise", ("category", "Exfiltration")),
                Preset("exfil-dashboard-002", "Research Exfil Replay", "Broad exfiltration tuning and replay preset.", "Research", ("packId", "carthago.exfiltration.v1"))
            ),
            References = References(
                Ref("MITRE ATT&CK", "Exfiltration Over Web Service", "https://attack.mitre.org/techniques/T1567/", "T1567"),
                Ref("MITRE ATT&CK", "Exfiltration Over C2 Channel", "https://attack.mitre.org/techniques/T1041/", "T1041"),
                Ref("Sigma", "Exfiltration detection guidance", "https://sigmahq.io/docs/")
            ),
            Changelog = new List<string> { "1.0.0 - Initial compiled exfiltration pack release." },
            SafetyNotes = new List<string>
            {
                "The local detection journal remains authoritative for all exfiltration findings.",
                "Recommendations never perform automatic destructive network actions."
            },
            License = "MIT"
        };

        public override ContentPackManifest Manifest => _manifest;
    }
}
