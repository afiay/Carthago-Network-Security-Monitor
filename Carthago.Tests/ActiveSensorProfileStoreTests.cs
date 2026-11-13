// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Carthago.Services;
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

public sealed class ActiveSensorProfileStoreTests : IDisposable
{
    private static readonly Guid AdapterId = Guid.Parse("02702701-1234-4321-9999-000000000001");
    private static readonly LocalLanInterface Adapter = new("lab", IPAddress.Parse("192.168.50.10"), IPAddress.Parse("255.255.255.0"));
    private static readonly IPAddress Target = IPAddress.Parse("192.168.50.11");
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "carthago-profiles-" + Guid.NewGuid().ToString("N"));
    private string DbPath => Path.Combine(_dir, "profiles.db");
    private ActiveSensorProfileStore Store() => new(DbPath);
    private static ActiveSensorProfile Profile(string name = "lab.example", int minutes = 5, bool history = true) =>
        ActiveSensorProfile.Create(AdapterId, Adapter, Target, ActiveSensorKind.Dns, name, 53,
            TimeSpan.FromMinutes(minutes), history);

    [Fact]
    public async Task ReopenedConfigurationRequiresFreshSessionApprovalAndExplicitExecution()
    {
        var profile = Profile();
        Assert.True(Store().Save(profile));
        var read = Store().Read();
        Assert.Null(read.Error);
        var saved = Assert.Single(read.Rows);
        Assert.Equal("Dns", saved.Sensor);
        Assert.True(saved.SaveHistory);
        int calls = 0;
        var manager = new ActiveSensorManager(resolve: _ => Adapter, probe: (_, _, _) =>
        { calls++; return Task.FromResult(new ActiveSensorRun("OK", true, null)); });
        Assert.Empty(manager.Snapshot());
        Assert.False(await manager.RunDueAsync(default));
        var approved = saved.ApproveForSession(AdapterId, Adapter, Target);
        Assert.NotEqual(profile.Id, approved.Id);
        manager.Add(approved);
        Assert.Equal(0, calls);
        Assert.True(await manager.RunDueAsync(default));
        Assert.Equal(1, calls);
    }

    [Theory]
    [InlineData("adapter")]
    [InlineData("source")]
    [InlineData("mask")]
    [InlineData("target")]
    public void ScopeMismatchRequiresNewConfiguration(string change)
    {
        var saved = SavedActiveSensorProfile.From(Profile());
        var id = change == "adapter" ? Guid.NewGuid() : AdapterId;
        var adapter = change == "source" ? Adapter with { Address = IPAddress.Parse("192.168.50.12") } :
            change == "mask" ? Adapter with { Mask = IPAddress.Parse("255.255.255.128") } : Adapter;
        var target = change == "target" ? IPAddress.Parse("192.168.50.13") : Target;
        Assert.Throws<ArgumentException>(() => saved.ApproveForSession(id, adapter, target));
    }

    [Fact]
    public void InvalidOrManualOnlyConfigurationRejected()
    {
        var profile = Profile();
        Assert.False(Store().Save(profile with { Kind = ActiveSensorKind.Snmp }));
        Assert.False(Store().Save(profile with { Kind = ActiveSensorKind.Gateway }));
        Assert.False(Store().Save(profile with { Interval = TimeSpan.FromSeconds(301) }));
        Assert.False(Store().Save(profile with { Adapter = Adapter with { Mask = IPAddress.Parse("255.0.255.0") } }));
        Assert.False(Store().Save(profile with { Target = IPAddress.Parse("8.8.8.8") }));
        Assert.Empty(Store().Read().Rows);
    }

    [Fact]
    public void StableConfigurationIdentityUpdatesIntervalAndHistoryOnly()
    {
        Assert.True(Store().Save(Profile()));
        var before = Assert.Single(Store().Read().Rows);
        Assert.True(Store().Save(Profile(minutes: 30, history: false)));
        var after = Assert.Single(Store().Read().Rows);
        Assert.Equal(before.Id, after.Id);
        Assert.Equal(30, after.IntervalMinutes);
        Assert.False(after.SaveHistory);
        Assert.True(Store().Delete(after.Id));
        Assert.False(Store().Delete(after.Id));
        Assert.Empty(Store().Read().Rows);
    }

    [Fact]
    public void CapacityIsBoundedButExistingConfigurationCanBeUpdated()
    {
        for (int i = 0; i < ActiveSensorProfileStore.MaxSavedProfiles; i++)
            Assert.True(Store().Save(Profile($"host{i}.example")));
        Assert.False(Store().Save(Profile("overflow.example")));
        Assert.True(Store().Save(Profile("host0.example", minutes: 60)));
        Assert.Equal(ActiveSensorProfileStore.MaxSavedProfiles, Store().Read().Rows.Count);
    }

    [Fact]
    public void CorruptStoreDoesNotLoadOrSilentlyReplaceOriginalFile()
    {
        Directory.CreateDirectory(_dir);
        var bytes = Enumerable.Repeat((byte)0xA5, 8192).ToArray();
        File.WriteAllBytes(DbPath, bytes);
        Assert.NotNull(Store().Read().Error);
        Assert.False(Store().Save(Profile()));
        Assert.Equal(bytes, File.ReadAllBytes(DbPath));
    }

    [Fact]
    public void TamperedSavedRecordCannotBeApproved()
    {
        var saved = SavedActiveSensorProfile.From(Profile());
        Assert.False((saved with { Target = "192.168.50.20" }).TryValidate(out _));
        Assert.False((saved with { Version = 2 }).TryValidate(out _));
        Assert.False((saved with { Sensor = "Snmp" }).TryValidate(out _));
        Assert.Throws<ArgumentException>(() => (saved with { Port = 54 }).ApproveForSession(AdapterId, Adapter, Target));
    }

    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }
}
