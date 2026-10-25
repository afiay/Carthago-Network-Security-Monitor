using Carthago.Services.Baseline;

namespace Carthago.Tests;

public sealed class BaselineStoreTests
{
    [Fact]
    public async Task ObserveAsync_AppendsDurablyWithoutRewritingTheEntireSnapshot()
    {
        var directory = Path.Combine(Path.GetTempPath(), "carthago-baseline-tests", Guid.NewGuid().ToString("N"));
        var store = new BaselineStore(new BaselineOptions { DirectoryPath = directory });
        var observation = new BaselineObservation("dns", "machine", "example.org",
            new DateTime(2026, 10, 25, 12, 0, 0, DateTimeKind.Utc), "test");

        await store.ObserveAsync(observation);
        await store.ObserveAsync(observation);

        Assert.True(File.Exists(Path.Combine(directory, "baseline-journal.jsonl")));
        Assert.False(File.Exists(Path.Combine(directory, "baseline.json")));
        var reopened = new BaselineStore(new BaselineOptions { DirectoryPath = directory });
        Assert.Equal(3, (await reopened.ObserveAsync(observation)).ObservationCount);
    }

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

    [Fact]
    public async Task Readiness_Requires_Durable_Diverse_Observations_Across_Time_And_Survives_Restart()
    {
        var directory = Path.Combine(Path.GetTempPath(), "carthago-baseline-tests", Guid.NewGuid().ToString("N"));
        var options = new BaselineOptions { DirectoryPath = directory, MinimumObservations = 4,
            MinimumDistinctKeys = 3, MinimumObservationSpan = TimeSpan.FromHours(2) };
        var store = new BaselineStore(options);
        var now = DateTime.UtcNow;
        Assert.False(store.Readiness.IsReady);
        for (var i = 0; i < 3; i++)
            await store.ObserveAsync(new BaselineObservation("dns.domain", $"host-{i}", $"domain-{i}.test",
                now.AddHours(-3 + i), "qtype=A"));
        Assert.False(store.Readiness.IsReady);
        await store.ObserveAsync(new BaselineObservation("dns.domain", "host-0", "domain-0.test", now, "qtype=A"));
        Assert.True(store.Readiness.IsReady);

        var reopened = new BaselineStore(options);
        Assert.False(reopened.Readiness.IsReady); // Unloaded state is never trusted.
        Assert.True((await reopened.GetReadinessAsync()).IsReady);
    }

    [Fact]
    public async Task Readiness_Fails_Closed_When_Journal_Contains_Malformed_Records()
    {
        var directory = Path.Combine(Path.GetTempPath(), "carthago-baseline-tests", Guid.NewGuid().ToString("N"));
        var options = new BaselineOptions { DirectoryPath = directory, MinimumObservations = 2,
            MinimumDistinctKeys = 2, MinimumObservationSpan = TimeSpan.FromMinutes(1) };
        var store = new BaselineStore(options);
        var now = DateTime.UtcNow;
        await store.ObserveAsync(new BaselineObservation("dns.domain", "host-1", "one.test", now.AddHours(-1), "qtype=A"));
        await store.ObserveAsync(new BaselineObservation("dns.domain", "host-2", "two.test", now, "qtype=A"));
        Assert.True(store.Readiness.IsReady);

        await File.AppendAllTextAsync(Path.Combine(directory, "baseline-journal.jsonl"), "not-valid-json\n");
        var reopened = new BaselineStore(options);
        var readiness = await reopened.GetReadinessAsync();
        Assert.False(readiness.IsReady);
        Assert.Contains(readiness.Blockers, item => item.Contains("corrupt", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Readiness_Rejects_Corrupt_Legacy_Snapshot_Without_Deleting_It()
    {
        var directory = Path.Combine(Path.GetTempPath(), "carthago-baseline-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var snapshot = Path.Combine(directory, "baseline.json");
        await File.WriteAllTextAsync(snapshot, "{invalid historical baseline");

        var readiness = await new BaselineStore(new BaselineOptions { DirectoryPath = directory }).GetReadinessAsync();
        Assert.False(readiness.IsReady);
        Assert.Contains(readiness.Blockers, item => item.Contains("corrupt", StringComparison.OrdinalIgnoreCase));
        Assert.Equal("{invalid historical baseline", await File.ReadAllTextAsync(snapshot));
    }
}
