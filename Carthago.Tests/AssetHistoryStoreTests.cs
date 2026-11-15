using System;
using System.IO;
using System.Linq;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class AssetHistoryStoreTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "carthago-assets-" + Guid.NewGuid().ToString("N"));
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 0, 0, 0, TimeSpan.Zero);
    private static TrafficRecord Local() => new()
    {
        IsTcp = true, TcpFlags = 0x12, Source = "192.168.1.10", Destination = "8.8.8.8",
        SourcePort = 443, DestinationPort = 50000, SrcIsLocalHost = true, CaptureBackend = "ETW"
    };
    private static ObservedAssetRegistry Registry(DateTimeOffset? started = null)
    {
        var registry = started.HasValue ? new ObservedAssetRegistry(started.Value) : new ObservedAssetRegistry();
        registry.Observe(Local(), Now);
        return registry;
    }
    [Fact]
    public void Checkpoint_Roundtrip_Survives_New_Store()
    {
        var registry = Registry();
        Assert.True(new AssetHistoryStore(_directory).Save(registry));
        var history = new AssetHistoryStore(_directory).Read();
        Assert.Null(history.Error);
        Assert.Equal(1, history.SessionCount);
        var row = Assert.Single(history.Rows);
        Assert.Equal(registry.SessionId.ToString("N"), row.SessionId);
        Assert.Equal("192.168.1.10", row.Asset.Addresses);
        Assert.Equal("443", row.Asset.Services);
        Assert.Equal(1L, row.Asset.Observations);
    }
    [Fact]
    public void Repeated_Checkpoints_Replace_Not_Double_Count()
    {
        var store = new AssetHistoryStore(_directory);
        var registry = Registry();
        Assert.True(store.Save(registry));
        registry.Observe(Local(), Now.AddSeconds(1));
        Assert.True(store.Save(registry));
        Assert.True(store.Save(registry));
        Assert.Single(Directory.GetFiles(_directory, "*.json"));
        Assert.Equal(2L, Assert.Single(store.Read().Rows).Asset.Observations);
    }
    [Fact]
    public void Separate_Sessions_Keep_Separate_Historical_Identity_Rows()
    {
        var store = new AssetHistoryStore(_directory);
        Assert.True(store.Save(Registry()));
        Assert.True(store.Save(Registry()));
        var history = store.Read();
        Assert.Equal(2, history.SessionCount);
        Assert.Equal(2, history.Rows.Select(r => r.SessionId).Distinct().Count());
        Assert.All(history.Rows, r => Assert.Equal(1L, r.Asset.Observations));
    }
    [Fact]
    public void Corrupt_Checkpoint_Is_Skipped_And_Not_Reported_As_Valid()
    {
        var store = new AssetHistoryStore(_directory);
        Assert.True(store.Save(Registry()));
        var path = Assert.Single(Directory.GetFiles(_directory, "*.json"));
        File.WriteAllText(path, "not-json");
        Assert.True(store.Save(Registry()));
        var history = store.Read();
        Assert.Equal(1, history.SessionCount);
        Assert.Single(history.Rows);
        Assert.NotNull(history.Error);
        Assert.Equal("not-json", File.ReadAllText(path));
    }
    [Fact]
    public void Retention_Is_Bounded_And_Empty_Sessions_Are_Not_Written()
    {
        var store = new AssetHistoryStore(_directory);
        Assert.True(store.Save(new ObservedAssetRegistry()));
        Assert.Equal(0, store.Read().SessionCount);
        for (int i = 0; i < AssetHistoryStore.MaxSessions + 2; i++)
            Assert.True(store.Save(Registry(Now.AddSeconds(i))));
        Assert.Equal(AssetHistoryStore.MaxSessions, Directory.GetFiles(_directory, "*.json").Length);
        Assert.Equal(AssetHistoryStore.MaxSessions, store.Read().SessionCount);
    }
    [Fact]
    public void Failed_Save_Is_Reported_And_Registry_Remains_Available()
    {
        Directory.CreateDirectory(_directory);
        var blocked = Path.Combine(_directory, "file");
        File.WriteAllText(blocked, "not a directory");
        var store = new AssetHistoryStore(blocked);
        var registry = Registry();
        Assert.False(store.Save(registry));
        Assert.NotNull(store.LastSaveError);
        Assert.Single(registry.Snapshot());
    }
    [Fact]
    public void Sealed_Registry_Rejects_Late_Observations()
    {
        var registry = Registry();
        registry.Seal();
        registry.Observe(Local(), Now.AddSeconds(1));
        Assert.Equal(1L, Assert.Single(registry.Snapshot()).Observations);
    }
    [Fact]
    public void Version_One_Asset_Only_Checkpoint_Remains_Readable()
    {
        Directory.CreateDirectory(_directory);
        var registry = Registry();
        var id = registry.SessionId;
        var started = registry.SessionStartedUtc;
        // Serialize the original schema, without any newer optional properties.
        var legacy = new { Version = 1, SessionId = id, StartedUtc = started, Assets = registry.Snapshot() };
        var path = Path.Combine(_directory, $"asset-{started.UtcDateTime.Ticks:D19}-{id:N}.json");
        File.WriteAllText(path, System.Text.Json.JsonSerializer.Serialize(legacy));
        var history = new AssetHistoryStore(_directory).Read();
        Assert.Null(history.Error);
        Assert.Equal(1, history.SessionCount);
        Assert.Equal("192.168.1.10", Assert.Single(history.Rows).Asset.Addresses);
        Assert.Empty(history.Communications!);
        Assert.Empty(history.Coverage!);
    }

    [Fact]
    public void Delayed_Periodic_Save_After_Final_Uses_Sealed_Registry_And_Separate_Session()
    {
        var store = new AssetHistoryStore(_directory);
        var original = Registry();
        Assert.True(store.Save(original));
        original.Observe(Local(), Now.AddSeconds(1));
        original.Seal();
        Assert.True(store.Save(original));
        var replacement = Registry();
        Assert.True(store.Save(replacement));

        // Maintenance retains the registry reference, not a prebuilt snapshot.
        original.Observe(Local(), Now.AddSeconds(2));
        Assert.True(store.Save(original));
        var history = new AssetHistoryStore(_directory).Read();
        Assert.Null(history.Error);
        Assert.Equal(2, history.SessionCount);
        Assert.Equal(2L, Assert.Single(history.Rows.Where(r => r.SessionId == original.SessionId.ToString("N"))).Asset.Observations);
        Assert.Equal(1L, Assert.Single(history.Rows.Where(r => r.SessionId == replacement.SessionId.ToString("N"))).Asset.Observations);
    }

    [Fact]
    public void Failed_Checkpoint_Can_Recover_On_Same_Store()
    {
        Directory.CreateDirectory(_directory);
        var blocked = Path.Combine(_directory, "blocked");
        File.WriteAllText(blocked, "not a directory");
        var store = new AssetHistoryStore(blocked);
        var registry = Registry();
        Assert.False(store.Save(registry));
        Assert.NotNull(store.LastSaveError);
        File.Delete(blocked);
        Assert.True(store.Save(registry));
        Assert.Null(store.LastSaveError);
        Assert.Equal(1L, Assert.Single(store.Read().Rows).Asset.Observations);
        Assert.Empty(Directory.GetFiles(blocked, "*.tmp"));
    }

    [Fact]
    public void Retention_Failure_Does_Not_Misreport_Persisted_Checkpoint()
    {
        var failCleanup = true;
        var store = new AssetHistoryStore(_directory, path =>
        {
            if (failCleanup) throw new IOException("injected retention failure");
            File.Delete(path);
        });
        for (int i = 0; i < AssetHistoryStore.MaxSessions; i++)
            Assert.True(store.Save(Registry(Now.AddSeconds(i))));

        var latest = Registry(Now.AddMinutes(1));
        Assert.True(store.Save(latest));
        var health = store.HealthSnapshot();
        Assert.Equal((long)AssetHistoryStore.MaxSessions + 1, health.Writes);
        Assert.Equal(0L, health.Failures);
        Assert.Contains("retention cleanup failed", health.LastError);
        Assert.Equal(AssetHistoryStore.MaxSessions + 1, Directory.GetFiles(_directory, "*.json").Length);
        Assert.Equal(AssetHistoryStore.MaxSessions, store.Read().SessionCount);

        failCleanup = false;
        Assert.True(store.Save(latest));
        Assert.Null(store.HealthSnapshot().LastError);
        Assert.Equal(AssetHistoryStore.MaxSessions, Directory.GetFiles(_directory, "*.json").Length);
        Assert.Empty(Directory.GetFiles(_directory, "*.tmp"));
    }

    [Fact]
    public void Persistent_Retention_Failure_Bounds_New_Sessions_And_Recovers()
    {
        bool blocked = true;
        var store = new AssetHistoryStore(_directory, path =>
        {
            if (blocked) throw new IOException("injected deletion denial");
            File.Delete(path);
        });
        for (int i = 0; i < AssetHistoryStore.MaxSessions; i++)
            Assert.True(store.Save(Registry(Now.AddSeconds(i))));
        var existing = Registry(Now.AddMinutes(1));
        Assert.True(store.Save(existing));
        var before = Directory.GetFiles(_directory, "*.json").OrderBy(p => p).ToArray();
        Assert.Equal(AssetHistoryStore.MaxSessions + 1, before.Length);
        var rejected = Registry(Now.AddMinutes(2));
        for (int i = 0; i < 3; i++)
        {
            Assert.False(store.Save(rejected));
            Assert.Equal(before, Directory.GetFiles(_directory, "*.json").OrderBy(p => p).ToArray());
            Assert.Contains("capacity exhausted", store.LastSaveError);
        }
        existing.Observe(Local(), Now.AddSeconds(1));
        Assert.True(store.Save(existing));
        Assert.Equal(2L, Assert.Single(store.Read().Rows.Where(r => r.SessionId == existing.SessionId.ToString("N"))).Asset.Observations);
        Assert.Equal(3L, store.HealthSnapshot().Failures);
        blocked = false;
        Assert.True(store.Save(rejected));
        Assert.Equal(AssetHistoryStore.MaxSessions, Directory.GetFiles(_directory, "*.json").Length);
        Assert.Null(store.LastSaveError);
        Assert.Empty(Directory.GetFiles(_directory, "*.tmp"));
    }

    [Fact]
    public void Delayed_Session_Outside_Retention_Window_Is_Rejected_Without_Changing_History()
    {
        var store = new AssetHistoryStore(_directory);
        var old = Registry(Now.AddMinutes(-1));
        Assert.True(store.Save(old));
        for (int i = 0; i < AssetHistoryStore.MaxSessions; i++)
            Assert.True(store.Save(Registry(Now.AddMinutes(i))));
        var before = Directory.GetFiles(_directory, "*.json").OrderBy(p => p).ToArray();
        Assert.Equal(AssetHistoryStore.MaxSessions, before.Length);
        Assert.False(store.Save(old));
        Assert.Contains("outside history retention window", store.LastSaveError);
        Assert.Equal(before, Directory.GetFiles(_directory, "*.json").OrderBy(p => p).ToArray());
        Assert.Equal(1L, store.HealthSnapshot().Failures);
        Assert.Equal(33L, store.HealthSnapshot().Writes);
        Assert.DoesNotContain(store.Read().Rows, r => r.SessionId == old.SessionId.ToString("N"));
        Assert.Empty(Directory.GetFiles(_directory, "*.tmp"));
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory)) Directory.Delete(_directory, recursive: true);
    }
}
