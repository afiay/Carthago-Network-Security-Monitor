using System.Text.Json;
using System.Text.Json.Serialization;
using Carthago.Engine.ContentPacks;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services.Benchmarking;
using Carthago.Services.Response;

namespace Carthago.Tests;

internal static class ContentPackTestHarness
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    internal static string CreateTempDirectory(string prefix = "carthago-content-pack")
    {
        var path = Path.Combine(Path.GetTempPath(), $"{prefix}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }

    internal static string RepoPath(params string[] segments)
        => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", Path.Combine(segments)));

    internal static ContentPackManifest GetPack(string packId)
        => CloneManifest(new CompiledContentPackRegistry().GetAvailablePacks().Single(pack =>
            string.Equals(pack.PackId, packId, StringComparison.OrdinalIgnoreCase)));

    internal static ContentPackManifest CloneManifest(ContentPackManifest manifest)
        => JsonSerializer.Deserialize<ContentPackManifest>(JsonSerializer.Serialize(manifest, Json), Json)
           ?? throw new InvalidOperationException("Failed to clone content pack manifest.");

    internal static ContentPackRegistry CreateRegistry(string rootDirectory, IEnumerable<IContentPackProvider>? providers = null)
        => new(new CompiledContentPackRegistry(providers), new ContentPackStore(rootDirectory));

    internal static ContentPackInstaller CreateInstaller(ContentPackRegistry registry)
        => new(registry, new ContentPackValidator(), new ContentPackBenchmarkRunner(registry));

    internal static ContentPackUninstaller CreateUninstaller(ContentPackRegistry registry)
        => new(registry);

    internal static RuleReplaySample LoadReplaySample(string relativePath)
    {
        using var stream = File.OpenRead(RepoPath(relativePath));
        return JsonSerializer.Deserialize<RuleReplaySample>(stream, Json)
            ?? throw new InvalidOperationException($"Unable to load replay sample {relativePath}.");
    }

    internal static ContentPackManifest CreateValidSyntheticManifest(
        string packId = "carthago.synthetic-test.v1",
        string ruleId = "CLOUD901")
    {
        return new ContentPackManifest
        {
            PackId = packId,
            Name = "Synthetic Test Pack",
            Version = "1.0.0",
            Description = "Synthetic manifest used to validate content-pack guardrails.",
            Category = "Synthetic",
            Author = "Carthago.Tests",
            MinimumCarthagoVersion = "1.0.0",
            Rules =
            {
                new ContentPackRule
                {
                    RuleId = ruleId,
                    Name = "Synthetic cloud alias",
                    Category = "Synthetic",
                    Description = "Synthetic content-pack rule for validation tests.",
                    Source = new ContentPackRuleSource { CoreRuleId = "R109" }
                }
            },
            Profiles =
            {
                new ContentPackProfileDefaults
                {
                    ProfileName = "SmallBusiness",
                    DefaultMode = RuleMode.Shadow,
                    Notes = "Synthetic validation profile."
                }
            },
            TuningDefaults =
            {
                new ContentPackTuningDefaults
                {
                    RuleId = ruleId,
                    RecommendedMode = RuleMode.Shadow,
                    Notes = "Synthetic validation tuning."
                }
            },
            ReplaySamples =
            {
                new ContentPackReplaySampleReference
                {
                    SampleId = "synthetic-benign",
                    RelativePath = @"Tests/RuleReplaySamples/benign/normal-browsing.json",
                    Classification = ReplaySampleClassification.Benign,
                    Purpose = "Synthetic benign validation sample.",
                    ExpectedRuleIds = { ruleId }
                }
            },
            Benchmarks =
            {
                new ContentPackBenchmarkExpectation
                {
                    ProfileName = "SmallBusiness",
                    MinimumPositivePassRate = 0.0,
                    MaximumCriticalFalsePositives = 1
                }
            },
            ResponseRecommendations =
            {
                new ContentPackResponseRecommendation
                {
                    RecommendationId = "synthetic-response-001",
                    Title = "Review synthetic detection",
                    Description = "Synthetic recommendation for validator coverage.",
                    ActionType = ResponseActionType.MarkForReview,
                    Safety = ResponseActionSafety.RecommendationOnly,
                    Automatic = false,
                    RequiresApproval = false,
                    SafetyWarning = "Do not auto-enforce synthetic recommendations.",
                    AppliesToRuleIds = { ruleId },
                    Steps = { "Review the detection journal entry." }
                }
            },
            References =
            {
                new RuleReference("Tests", "Synthetic content-pack reference", "https://example.test/content-pack")
            },
            SafetyNotes = { "Synthetic safety note." },
            License = "MIT"
        };
    }

    internal static DetectionEvent CreateDetection(
        string ruleId,
        string eventId,
        double confidence = 0.90,
        string sourceIp = "10.20.30.40",
        string destinationIp = "203.0.113.20")
        => new()
        {
            EventId = eventId,
            RuleId = ruleId,
            RuleName = ruleId,
            ConfidenceScore = confidence,
            Description = "Synthetic content-pack detection.",
            Summary = "Synthetic content-pack detection.",
            Evidence = "Synthetic evidence",
            StructuredEvidence = new DetectionEvidenceSet(
                new[] { new DetectionEvidenceItem("event", eventId, "test") },
                "Synthetic evidence"),
            TimestampUtc = new DateTime(2026, 4, 29, 12, 0, 0, DateTimeKind.Utc),
            SourceIp = sourceIp,
            DestinationIp = destinationIp,
            DestinationHost = "example.test",
            DestinationPort = 443,
            Protocol = "HTTP",
            Severity = SeverityLevel.High
        };
}
