using System.Text.Json;

namespace Carthago.Tests;

public sealed class ContentPackDocumentationTests
{
    [Fact]
    public void Content_pack_docs_exist_and_include_required_sections()
    {
        var docs = new[]
        {
            "CloudSaasPack.md",
            "ActiveDirectoryPack.md",
            "KubernetesPack.md",
            "Microsoft365Pack.md",
            "DevOpsPack.md",
            "IoTHomePack.md",
            "OTIndustrialPack.md",
            "MalwareC2Pack.md",
            "ExfiltrationPack.md",
            "README.md"
        };

        foreach (var doc in docs)
        {
            var path = ContentPackTestHarness.RepoPath("Docs", "ContentPacks", doc);
            Assert.True(File.Exists(path), $"Expected content-pack doc {path} to exist.");
            var text = File.ReadAllText(path);
            if (!string.Equals(doc, "README.md", StringComparison.OrdinalIgnoreCase))
            {
                Assert.Contains("Telemetry requirements", text, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("Safety notes", text, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("Response recommendations", text, StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    [Fact]
    public void Content_pack_config_samples_exist_and_expose_expected_configuration_sections()
    {
        var samples = new[]
        {
            "cloud-saas.sample.json",
            "active-directory.sample.json",
            "kubernetes.sample.json",
            "microsoft365.sample.json",
            "devops.sample.json",
            "iot-home.sample.json",
            "ot-industrial.sample.json",
            "malware-c2.sample.json",
            "exfiltration.sample.json"
        };

        foreach (var sample in samples)
        {
            var path = ContentPackTestHarness.RepoPath("config", "samples", "content-packs", sample);
            Assert.True(File.Exists(path), $"Expected content-pack config sample {path} to exist.");

            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var root = document.RootElement;
            Assert.True(root.TryGetProperty("install", out _));
            Assert.True(root.TryGetProperty("enable", out _));
            Assert.True(root.TryGetProperty("profileDefaults", out _));
            Assert.True(root.TryGetProperty("approvedAssets", out _));
            Assert.True(root.TryGetProperty("thresholds", out _));
            Assert.True(root.TryGetProperty("modeOverrides", out _));
            Assert.True(root.TryGetProperty("benchmark", out _));
            Assert.True(root.TryGetProperty("responseRecommendations", out _));
        }
    }
}
