using Carthago.Engine.ContentPacks;

namespace Carthago.Tests;

public sealed class ContentPackLifecycleTests
{
    [Fact]
    public void Dry_run_changes_no_installed_state_but_records_plan_history()
    {
        var root = ContentPackTestHarness.CreateTempDirectory();
        var registry = ContentPackTestHarness.CreateRegistry(root);
        var installer = ContentPackTestHarness.CreateInstaller(registry);
        var manifest = ContentPackTestHarness.GetPack("carthago.cloud-saas.v1");

        var plan = installer.DryRun(manifest, enableAfterInstall: true);
        var state = registry.LoadState();

        Assert.True(plan.DryRun);
        Assert.True(plan.Validation.IsValid);
        Assert.Empty(state.InstalledPacks);
        Assert.Single(state.DryRunPlanHistory);
        Assert.Equal(manifest.PackId, state.DryRunPlanHistory[0].PackId);
    }

    [Fact]
    public void Install_enable_disable_and_uninstall_preserve_history_while_hiding_future_pack_artifacts()
    {
        var root = ContentPackTestHarness.CreateTempDirectory();
        var historyRoot = ContentPackTestHarness.CreateTempDirectory("carthago-history");
        var historicalJournal = Path.Combine(historyRoot, "detections-2026-04-29.jsonl");
        File.WriteAllText(historicalJournal, "{\"eventId\":\"historic-1\",\"ruleId\":\"CLOUD006\"}" + Environment.NewLine);

        var registry = ContentPackTestHarness.CreateRegistry(root);
        var installer = ContentPackTestHarness.CreateInstaller(registry);
        var uninstaller = ContentPackTestHarness.CreateUninstaller(registry);
        var manifest = ContentPackTestHarness.GetPack("carthago.cloud-saas.v1");

        var install = installer.Install(manifest, enableAfterInstall: false);
        Assert.True(install.Succeeded);
        Assert.Single(registry.GetInstalledPacks());
        Assert.Empty(registry.GetActiveRules());

        var enable = installer.Enable(manifest.PackId);
        Assert.True(enable.Succeeded);
        Assert.Equal(50, registry.GetActiveRules().Count);
        Assert.NotEmpty(registry.GetEnabledHunts());
        Assert.NotEmpty(registry.BuildRecommendations(manifest.PackId, "CLOUD006", "evt-1", "inc-1"));

        var disable = installer.Disable(manifest.PackId);
        Assert.True(disable.Succeeded);
        Assert.Empty(registry.GetActiveRules());
        Assert.Empty(registry.GetEnabledHunts());
        Assert.Empty(registry.BuildRecommendations(manifest.PackId, "CLOUD006", "evt-1", "inc-1"));

        var uninstall = uninstaller.Uninstall(manifest.PackId);
        Assert.True(uninstall.Succeeded);
        Assert.Empty(registry.GetInstalledPacks());
        Assert.False(File.Exists(new ContentPackStore(root).GetManifestPath(manifest.PackId)));
        Assert.True(File.Exists(historicalJournal));
        Assert.Contains(uninstall.Warnings, warning => warning.Contains("preserved", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Disabled_pack_rule_referenced_by_config_is_recorded_as_skipped()
    {
        var root = ContentPackTestHarness.CreateTempDirectory();
        var registry = ContentPackTestHarness.CreateRegistry(root);

        var activation = registry.CreateActivation(new ContentPackActivationOptions
        {
            ConfiguredRuleIds = new[] { "CLOUD001", "AD001" }
        });

        Assert.Empty(activation.ActiveRules);
        Assert.Contains("CLOUD001", activation.SkippedConfiguredRuleIds);
        Assert.Contains("AD001", activation.SkippedConfiguredRuleIds);
    }

    [Fact]
    public void Upgrade_preserves_override_notes_surfaces_deprecations_and_rejects_silent_removals_or_unapproved_downgrades()
    {
        var root = ContentPackTestHarness.CreateTempDirectory();
        var registry = ContentPackTestHarness.CreateRegistry(root);
        var installer = ContentPackTestHarness.CreateInstaller(registry);
        var manifest = ContentPackTestHarness.GetPack("carthago.cloud-saas.v1");

        Assert.True(installer.Install(manifest, enableAfterInstall: true).Succeeded);

        var upgraded = ContentPackTestHarness.CloneManifest(manifest);
        upgraded.Version = "1.1.0";
        upgraded.Changelog.Add("1.1.0 - Added deprecation metadata for one cloud rule.");
        upgraded.Rules[0].Deprecated = true;

        var upgradePlan = installer.PlanUpgrade(upgraded);
        Assert.Empty(upgradePlan.Errors);
        Assert.Contains(upgradePlan.PreservedUserOverrideNotes, note => note.Contains("overrides remain authoritative", StringComparison.OrdinalIgnoreCase));

        var upgradeResult = installer.Upgrade(upgraded);
        Assert.True(upgradeResult.Succeeded);
        Assert.Contains("1.1.0", string.Join(" ", upgradeResult.InstalledPack!.Changelog));
        Assert.True(registry.LoadInstalledManifest(manifest.PackId)!.Rules[0].Deprecated);
        Assert.True(registry.GetAllAvailableRuleRegistrations()
            .Single(registration => string.Equals(registration.PackId, manifest.PackId, StringComparison.OrdinalIgnoreCase)
                && string.Equals(registration.Rule.RuleId, upgraded.Rules[0].RuleId, StringComparison.OrdinalIgnoreCase))
            .CompiledRule!.Deprecated);

        var downgrade = ContentPackTestHarness.CloneManifest(upgraded);
        downgrade.Version = "0.9.0";
        var downgradePlan = installer.PlanUpgrade(downgrade);
        Assert.True(downgradePlan.IsDowngrade);
        Assert.Contains(downgradePlan.Errors, error => error.Contains("explicit approval", StringComparison.OrdinalIgnoreCase));

        var removalRoot = ContentPackTestHarness.CreateTempDirectory();
        var removalRegistry = ContentPackTestHarness.CreateRegistry(removalRoot);
        var removalInstaller = ContentPackTestHarness.CreateInstaller(removalRegistry);
        Assert.True(removalInstaller.Install(manifest, enableAfterInstall: false).Succeeded);
        var removedRuleManifest = ContentPackTestHarness.CloneManifest(manifest);
        removedRuleManifest.Version = "1.1.0";
        removedRuleManifest.Rules.RemoveAt(0);
        var removalPlan = removalInstaller.PlanUpgrade(removedRuleManifest);
        Assert.Contains(removalPlan.Errors, error => error.Contains("cannot be removed until it is first shipped as deprecated", StringComparison.OrdinalIgnoreCase));
    }
}
