using Carthago.Services.Baseline;

namespace Carthago.Tests;

public sealed class BaselineStoreTests
{
    [Fact]
    public async Task ObserveAsync_PersistsKnownObservationsAcrossInstances()
    {
        var directory = Path.Combine(Path.GetTempPath(), "carthago-baseline-tests", Guid.NewGuid().ToString("N"));
        var observation = new BaselineObservation("dns.domain", "192.0.2.10", "example.test",
            new DateTime(2026, 4, 29, 12, 0, 0, DateTimeKind.Utc), "DNS query");

        var initial = new BaselineStore(new BaselineOptions { DirectoryPath = directory });
        Assert.True((await initial.ObserveAsync(observation)).IsFirstSeen);

        var reopened = new BaselineStore(new BaselineOptions { DirectoryPath = directory });
        var next = await reopened.ObserveAsync(observation);

        Assert.True(next.IsKnown);
        Assert.False(next.IsFirstSeen);
        Assert.Equal(2, next.ObservationCount);
    }

    [Fact]
    public async Task ObserveAsync_DoesNotConfuseDifferentSubjects()
    {
        var directory = Path.Combine(Path.GetTempPath(), "carthago-baseline-tests", Guid.NewGuid().ToString("N"));
        var store = new BaselineStore(new BaselineOptions { DirectoryPath = directory });
        var timestamp = new DateTime(2026, 4, 29, 12, 0, 0, DateTimeKind.Utc);

        await store.ObserveAsync(new BaselineObservation("dns.domain", "host-a", "example.test", timestamp, ""));
        var other = await store.ObserveAsync(new BaselineObservation("dns.domain", "host-b", "example.test", timestamp, ""));

        Assert.True(other.IsFirstSeen);
        Assert.Equal(1, other.ObservationCount);
    }

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
