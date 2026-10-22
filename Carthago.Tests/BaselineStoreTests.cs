using Carthago.Services.Baseline;

namespace Carthago.Tests;

public sealed class BaselineStoreTests
{
    [Fact]
    public async Task ClearAsync_resets_observation_history_for_replay_isolation()
    {
        var directory = Path.Combine(Path.GetTempPath(), "carthago-baseline-tests", Guid.NewGuid().ToString("N"));
        var store = new BaselineStore(new BaselineOptions { DirectoryPath = directory });
        var observation = new BaselineObservation(
            "dns.dga-candidate",
            "10.0.1.10",
            "x9q8v7m6n5p4t3k2rz.example",
            new DateTime(2026, 4, 29, 12, 0, 0, DateTimeKind.Utc),
            "qtype=A");

        var first = await store.ObserveAsync(observation);
        var second = await store.ObserveAsync(observation);

        Assert.True(first.IsFirstSeen);
        Assert.True(second.IsKnown);
        Assert.Equal(2, second.ObservationCount);

        await store.ClearAsync();

        var afterClear = await store.ObserveAsync(observation);

        Assert.True(afterClear.IsFirstSeen);
        Assert.False(afterClear.IsKnown);
        Assert.Equal(1, afterClear.ObservationCount);
    }
}
