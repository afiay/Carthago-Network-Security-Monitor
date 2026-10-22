using Carthago.Engine.ContentPacks;
using Carthago.Services.Response;

namespace Carthago.Tests;

public sealed class ContentPackValidationTests
{
    private readonly ContentPackValidator _validator = new();

    [Fact]
    public void Validator_rejects_duplicate_pack_ids_rule_ids_core_collisions_and_invalid_formats()
    {
        var manifest = ContentPackTestHarness.CreateValidSyntheticManifest();

        var duplicatePack = _validator.Validate(manifest, new[] { manifest.PackId });
        Assert.Contains(duplicatePack.Errors, error => error.Contains("Duplicate content pack id", StringComparison.OrdinalIgnoreCase));

        var duplicateRule = ContentPackTestHarness.CloneManifest(manifest);
        duplicateRule.Rules.Add(new ContentPackRule
        {
            RuleId = duplicateRule.Rules[0].RuleId,
            Name = "Duplicate synthetic rule",
            Category = "Synthetic",
            Description = "Duplicate synthetic rule",
            Source = new ContentPackRuleSource { CoreRuleId = "R109" }
        });
        var duplicateRuleResult = _validator.Validate(duplicateRule);
        Assert.Contains(duplicateRuleResult.Errors, error => error.Contains("Duplicate pack rule IDs", StringComparison.OrdinalIgnoreCase));

        var invalidFormat = ContentPackTestHarness.CreateValidSyntheticManifest(ruleId: "cloud-001");
        var invalidFormatResult = _validator.Validate(invalidFormat);
        Assert.Contains(invalidFormatResult.Errors, error => error.Contains("Invalid pack rule ID format", StringComparison.OrdinalIgnoreCase));

        var coreCollision = ContentPackTestHarness.CreateValidSyntheticManifest(ruleId: "R109");
        var coreCollisionResult = _validator.Validate(coreCollision);
        Assert.Contains(coreCollisionResult.Errors, error => error.Contains("collides with core rule ID", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Validator_rejects_unsupported_versions_mandatory_journal_disable_and_unsafe_install_operations()
    {
        var manifest = ContentPackTestHarness.CreateValidSyntheticManifest();
        manifest.MinimumCarthagoVersion = "99.0.0";
        manifest.DisableMandatoryJournaling = true;
        manifest.InstallOperations.Add("delete historical detections");

        var result = _validator.Validate(manifest);

        Assert.Contains(result.Errors, error => error.Contains("unsupported Carthago version", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Errors, error => error.Contains("cannot disable mandatory journaling", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Errors, error => error.Contains("Unsafe install operations", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Validator_rejects_immutable_overrides_unknown_profiles_unknown_tuning_targets_and_invalid_replay_references()
    {
        var manifest = ContentPackTestHarness.CreateValidSyntheticManifest();
        manifest.Profiles[0].ProfileName = "UnknownProfile";
        manifest.TuningDefaults[0].RuleId = "CLOUD999";
        manifest.ExistingRuleOverrides.Add(new ContentPackTuningDefaults
        {
            RuleId = "R109",
            FieldOverrides = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["RuleId"] = "R110",
                ["DashboardPreset"] = "bad"
            }
        });
        manifest.ReplaySamples[0].ExpectedRuleIds.Add("CLOUD999");

        var result = _validator.Validate(manifest);

        Assert.Contains(result.Errors, error => error.Contains("Unknown profile default", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Errors, error => error.Contains("Tuning default references unknown pack rule ID", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Errors, error => error.Contains("immutable field RuleId", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Errors, error => error.Contains("modify UI preferences", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Errors, error => error.Contains("references unknown pack rule", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Validator_rejects_automatic_destructive_response_recommendations()
    {
        var manifest = ContentPackTestHarness.CreateValidSyntheticManifest();
        manifest.ResponseRecommendations[0].ActionType = ResponseActionType.BlockDomain;
        manifest.ResponseRecommendations[0].Safety = ResponseActionSafety.Destructive;
        manifest.ResponseRecommendations[0].Automatic = true;

        var result = _validator.Validate(manifest);

        Assert.Contains(result.Errors, error => error.Contains("destructive automatic execution", StringComparison.OrdinalIgnoreCase));
    }
}
