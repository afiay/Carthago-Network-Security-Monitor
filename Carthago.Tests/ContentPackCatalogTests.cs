using Carthago.Engine.ContentPacks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;

namespace Carthago.Tests;

public sealed class ContentPackCatalogTests
{
    [Fact]
    public void Core_rule_catalog_remains_immutable_and_available_catalog_expands_to_954_rules()
    {
        var coreIds = RuleCatalog.All.Select(static descriptor => descriptor.RuleId).ToArray();
        Assert.Equal(544, coreIds.Length);
        for (var index = 1; index <= 544; index++)
            Assert.Equal($"R{index:000}", coreIds[index - 1]);

        var availableIds = RuleCatalog.AllAvailable.Select(static descriptor => descriptor.RuleId).ToArray();
        Assert.Equal(954, availableIds.Length);
        Assert.Equal(410, availableIds.Count(id => !RuleIdValidator.IsCoreRuleId(id)));
        Assert.Empty(availableIds.GroupBy(id => id, StringComparer.OrdinalIgnoreCase).Where(group => group.Count() > 1));
        Assert.Empty(RuleCatalog.ValidateAvailable());
    }

    [Fact]
    public void Compiled_registry_lists_expected_packs_and_rule_counts()
    {
        var registry = new CompiledContentPackRegistry();
        var providers = registry.Providers;

        Assert.Equal(9, providers.Count);
        Assert.Equal(
            new[]
            {
                "carthago.active-directory.v1",
                "carthago.cloud-saas.v1",
                "carthago.devops.v1",
                "carthago.exfiltration.v1",
                "carthago.iot-home.v1",
                "carthago.kubernetes.v1",
                "carthago.malware-c2.v1",
                "carthago.microsoft365.v1",
                "carthago.ot-industrial.v1"
            },
            providers.Select(static provider => provider.Manifest.PackId).OrderBy(static id => id, StringComparer.OrdinalIgnoreCase).ToArray());

        var counts = providers.ToDictionary(static provider => provider.Manifest.PackId, static provider => provider.Manifest.Rules.Count, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(50, counts["carthago.cloud-saas.v1"]);
        Assert.Equal(50, counts["carthago.active-directory.v1"]);
        Assert.Equal(40, counts["carthago.kubernetes.v1"]);
        Assert.Equal(40, counts["carthago.microsoft365.v1"]);
        Assert.Equal(40, counts["carthago.devops.v1"]);
        Assert.Equal(40, counts["carthago.iot-home.v1"]);
        Assert.Equal(50, counts["carthago.ot-industrial.v1"]);
        Assert.Equal(60, counts["carthago.malware-c2.v1"]);
        Assert.Equal(40, counts["carthago.exfiltration.v1"]);
        Assert.Equal(410, counts.Values.Sum());
        Assert.Equal(410, registry.GetAllRuleRegistrations().Count);
    }

    [Fact]
    public void Pack_rules_have_prefixed_ids_intelligence_and_telemetry_without_core_collisions()
    {
        var coreRuleIds = RuleCatalog.All.Select(static descriptor => descriptor.RuleId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var registrations = new CompiledContentPackRegistry().GetAllRuleRegistrations();

        Assert.All(registrations, registration =>
        {
            Assert.True(RuleIdValidator.IsPackRuleId(registration.Rule.RuleId), $"Expected a valid prefixed pack RuleId, got {registration.Rule.RuleId}.");
            Assert.DoesNotContain(registration.Rule.RuleId, coreRuleIds);
            Assert.NotNull(registration.CompiledRule);
            Assert.NotNull(registration.CompiledRule!.Intelligence);
            Assert.NotEmpty(registration.CompiledRule.Intelligence.TelemetryRequirements);
        });
    }
}
