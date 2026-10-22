using Carthago.Engine.ContentPacks;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services.Hunting;

namespace Carthago.Tests;

public sealed class ContentPackBenchmarkAndHuntTests
{
    [Fact]
    public void Benchmark_runs_for_installed_pack_and_stores_result_artifacts()
    {
        var root = ContentPackTestHarness.CreateTempDirectory();
        var output = ContentPackTestHarness.CreateTempDirectory("carthago-content-pack-benchmark");
        var registry = ContentPackTestHarness.CreateRegistry(root);
        var installer = ContentPackTestHarness.CreateInstaller(registry);
        var manifest = ContentPackTestHarness.GetPack("carthago.cloud-saas.v1");

        var install = installer.Install(manifest, enableAfterInstall: true, runBenchmark: true, benchmarkOutputDirectory: output);
        var state = registry.LoadState();
        var benchmark = Assert.Single(state.InstalledPacks).LastBenchmarkResult;

        Assert.True(install.Succeeded);
        Assert.NotNull(benchmark);
        Assert.Equal(manifest.PackId, benchmark!.PackId);
        Assert.True(File.Exists(benchmark.JsonPath));
        Assert.True(File.Exists(benchmark.MarkdownPath));
    }

    [Fact]
    public void Benchmark_reports_failures_telemetry_gaps_and_low_critical_false_positive_volume_when_expectations_are_not_met()
    {
        var root = ContentPackTestHarness.CreateTempDirectory();
        var output = ContentPackTestHarness.CreateTempDirectory("carthago-content-pack-benchmark-failure");
        var registry = ContentPackTestHarness.CreateRegistry(root);
        var installer = ContentPackTestHarness.CreateInstaller(registry);
        var manifest = ContentPackTestHarness.GetPack("carthago.cloud-saas.v1");
        manifest.Version = "1.0.1";
        manifest.ReplaySamples[0].ExpectedRuleIds.Clear();
        manifest.ReplaySamples[0].ExpectedRuleIds.Add("CLOUD050");

        var install = installer.Install(manifest, enableAfterInstall: true, runBenchmark: true, benchmarkOutputDirectory: output);
        var summary = Assert.Single(registry.LoadState().InstalledPacks).LastBenchmarkResult;

        Assert.True(install.Succeeded);
        Assert.NotNull(summary);
        Assert.False(summary!.PassedExpectations);
        Assert.NotEmpty(summary.FailedExpectations);
        Assert.NotEmpty(summary.TelemetryGaps);
        Assert.True(summary.CriticalFalsePositiveCount <= 1, $"Expected benign critical spam to stay near zero, but saw {summary.CriticalFalsePositiveCount}.");
    }

    [Fact]
    public async Task Compiled_pack_rule_emits_structured_evidence_when_it_matches()
    {
        var rule = new CompiledContentPackRegistry().GetAllRuleRegistrations()
            .Single(registration => string.Equals(registration.Rule.RuleId, "AD041", StringComparison.OrdinalIgnoreCase))
            .CompiledRule!;
        var sample = ContentPackTestHarness.LoadReplaySample(@"Tests/RuleReplaySamples/malicious/ad-psremoting-encoded-command.json");

        var events = new List<Carthago.Models.DetectionEvent>();
        foreach (var record in sample.Records)
        {
            var result = await rule.EvaluateAsync(new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UtcNow));
            events.AddRange(result.Events);
        }

        var evt = Assert.Single(events);
        Assert.NotNull(evt.StructuredEvidence);
        Assert.NotEmpty(evt.StructuredEvidence!.Items);
        Assert.Contains(evt.StructuredEvidence.Items, item => string.Equals(item.Key, "content_pack_id", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Enabled_hunts_register_only_for_enabled_packs_and_filter_without_mutating_detections()
    {
        var root = ContentPackTestHarness.CreateTempDirectory();
        var registry = ContentPackTestHarness.CreateRegistry(root);
        var installer = ContentPackTestHarness.CreateInstaller(registry);
        var manifest = ContentPackTestHarness.GetPack("carthago.cloud-saas.v1");

        Assert.True(installer.Install(manifest, enableAfterInstall: true).Succeeded);
        var hunt = Assert.Single(registry.GetEnabledHunts().Where(item => string.Equals(item.PackId, manifest.PackId, StringComparison.OrdinalIgnoreCase)).Take(1));
        var detections = new List<Carthago.Models.DetectionEvent>
        {
            ContentPackTestHarness.CreateDetection(hunt.Query.RuleId!, "evt-match"),
            ContentPackTestHarness.CreateDetection("CLOUD999", "evt-other")
        };

        var result = new HuntQueryEngine().Execute(hunt.Query, detections);

        Assert.Single(result.Detections);
        Assert.Equal("evt-match", result.Detections[0].EventId);
        Assert.Contains("evt-match", result.SourceIds);
        Assert.Equal(2, detections.Count);
        Assert.Equal(new[] { "evt-match", "evt-other" }, detections.Select(static detection => detection.EventId).ToArray());

        Assert.True(installer.Disable(manifest.PackId).Succeeded);
        Assert.Empty(registry.GetEnabledHunts());
    }

    [Fact]
    public void Recommendations_cite_evidence_require_approval_when_needed_and_ot_pack_carries_safety_warning()
    {
        var root = ContentPackTestHarness.CreateTempDirectory();
        var registry = ContentPackTestHarness.CreateRegistry(root);
        var installer = ContentPackTestHarness.CreateInstaller(registry);

        Assert.True(installer.Install(ContentPackTestHarness.GetPack("carthago.active-directory.v1"), enableAfterInstall: true).Succeeded);
        Assert.True(installer.Install(ContentPackTestHarness.GetPack("carthago.ot-industrial.v1"), enableAfterInstall: true).Succeeded);

        var adRecommendations = registry.BuildRecommendations("carthago.active-directory.v1", "AD020", "evt-123", "inc-456");
        Assert.NotEmpty(adRecommendations);
        Assert.All(adRecommendations, action =>
        {
            Assert.Equal("evt-123", action.SourceEventId);
            Assert.Equal("inc-456", action.SourceIncidentId);
            Assert.Equal("AD020", action.SourceRuleId);
        });
        Assert.Contains(adRecommendations, action => action.RequiresApproval);

        var otManifest = registry.LoadInstalledManifest("carthago.ot-industrial.v1");
        Assert.NotNull(otManifest);
        Assert.Contains(otManifest!.ResponseRecommendations, recommendation =>
            recommendation.SafetyWarning.Contains("Do not auto-block", StringComparison.OrdinalIgnoreCase));
    }
}
