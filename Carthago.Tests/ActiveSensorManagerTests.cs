// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services;
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

public sealed class ActiveSensorManagerTests
{
    private static readonly Guid AdapterId = Guid.Parse("02702701-1234-4321-9999-000000000001");
    private static readonly LocalLanInterface Adapter = new("test", IPAddress.Parse("192.168.1.130"), IPAddress.Parse("255.255.255.128"));
    private static readonly IPAddress Target = IPAddress.Parse("192.168.1.131");
    private static ActiveSensorProfile Profile(ActiveSensorKind kind = ActiveSensorKind.Tcp, bool save = false) =>
        ActiveSensorProfile.Create(AdapterId, Adapter, Target, kind, "lab.example", 443, TimeSpan.FromMinutes(5), save);
    private static readonly DateTimeOffset Initial = new(2026, 11, 13, 0, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData("Gateway")]
    [InlineData("Snmp")]
    public void ManualOnlyRejected(string kind) => Assert.Throws<ArgumentException>(() => Profile(Enum.Parse<ActiveSensorKind>(kind)));

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(1441)]
    public void InvalidIntervalRejected(int minutes) => Assert.Throws<ArgumentException>(() =>
        ActiveSensorProfile.Create(AdapterId, Adapter, Target, ActiveSensorKind.Tcp, "", 0, TimeSpan.FromMinutes(minutes), false));

    [Fact]
    public void PublicTargetRejected() => Assert.Throws<ArgumentException>(() =>
        ActiveSensorProfile.Create(AdapterId, Adapter, IPAddress.Parse("8.8.8.8"), ActiveSensorKind.Tcp, "", 0, TimeSpan.FromMinutes(5), false));

    [Fact]
    public async Task AddDoesNotProbeAndRunsOnlyWhenDue()
    {
        var now = Initial; int calls = 0;
        var manager = new ActiveSensorManager(() => now, _ => Adapter,
            (_, _, _) => { calls++; return Task.FromResult(new ActiveSensorRun("OK", true, null)); });
        manager.Add(Profile());
        Assert.Equal(0, calls);
        Assert.True(await manager.RunDueAsync(default));
        Assert.False(await manager.RunDueAsync(default));
        now = now.AddMinutes(5);
        Assert.True(await manager.RunDueAsync(default));
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task FailureBackoffAndRecovery()
    {
        var now = Initial; bool responsive = false;
        var manager = new ActiveSensorManager(() => now, _ => Adapter,
            (_, _, _) => Task.FromResult(new ActiveSensorRun("result", responsive, null)));
        manager.Add(Profile());
        await manager.RunDueAsync(default);
        Assert.Equal(now.AddMinutes(10), Assert.Single(manager.Snapshot()).NextDueUtc);
        now = now.AddMinutes(10);
        await manager.RunDueAsync(default);
        Assert.Equal(now.AddMinutes(20), Assert.Single(manager.Snapshot()).NextDueUtc);
        responsive = true; now = now.AddMinutes(20);
        await manager.RunDueAsync(default);
        var state = Assert.Single(manager.Snapshot());
        Assert.Equal(0, state.ConsecutiveFailures);
        Assert.Equal(now.AddMinutes(5), state.NextDueUtc);
        Assert.Equal(TimeSpan.FromHours(24), ActiveSensorManager.NextDelay(TimeSpan.FromHours(12), 30));
    }

    [Fact]
    public async Task ScopeChangeBlocksUntilReapproved()
    {
        int calls = 0;
        var manager = new ActiveSensorManager(() => Initial, _ => null,
            (_, _, _) => { calls++; return Task.FromResult(new ActiveSensorRun("OK", true, null)); });
        var p = Profile(); manager.Add(p);
        Assert.True(await manager.RunDueAsync(default));
        Assert.False(await manager.RunDueAsync(default));
        Assert.True(Assert.Single(manager.Snapshot()).ScopeBlocked);
        Assert.Equal(0, calls);
        Assert.True(manager.Remove(p.Id));
        Assert.Empty(manager.Snapshot());
    }

    [Fact]
    public async Task ConcurrentTicksNeverOverlapAndCancellationReleasesGate()
    {
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var manager = new ActiveSensorManager(() => Initial, _ => Adapter,
            async (_, _, token) => { entered.TrySetResult(true); await Task.Delay(Timeout.Infinite, token); return new("OK", true, null); });
        var p = Profile(); manager.Add(p);
        using var cts = new CancellationTokenSource();
        var first = manager.RunDueAsync(cts.Token);
        await entered.Task;
        Assert.False(await manager.RunDueAsync(default));
        Assert.False(manager.Remove(p.Id));
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
        Assert.False(Assert.Single(manager.Snapshot()).Running);
        Assert.True(manager.Remove(p.Id));
    }

    [Theory]
    [InlineData(false, true, "Not requested")]
    [InlineData(true, true, "Saved")]
    [InlineData(true, false, "Storage failed")]
    public async Task PersistenceOptInAndStorageFailureSeparate(bool save, bool writeSucceeds, string expected)
    {
        int writes = 0;
        var manager = new ActiveSensorManager(() => Initial, _ => Adapter,
            (_, _, _) => Task.FromResult(new ActiveSensorRun("OK", true, new ActiveEvidenceRow())),
            _ => { writes++; return writeSucceeds; });
        manager.Add(Profile(save: save));
        await manager.RunDueAsync(default);
        var state = Assert.Single(manager.Snapshot());
        Assert.Equal(expected, state.HistoryStatus);
        Assert.Equal("OK", state.LastOutcome);
        Assert.Equal(0, state.ConsecutiveFailures);
        Assert.Equal(save ? 1 : 0, writes);
    }

    [Fact]
    public void DuplicateAndCapacityRejected()
    {
        var manager = new ActiveSensorManager(() => Initial);
        manager.Add(Profile());
        Assert.Throws<InvalidOperationException>(() => manager.Add(Profile()));
        for (int i = 0; i < ActiveSensorManager.MaxProfiles - 1; i++)
            manager.Add(ActiveSensorProfile.Create(AdapterId, Adapter, Target, ActiveSensorKind.Dns,
                $"host{i}.example", 53, TimeSpan.FromMinutes(5), false));
        Assert.Throws<InvalidOperationException>(() => manager.Add(Profile(ActiveSensorKind.Http)));
    }

    [Fact]
    public async Task MultipleDueProfilesRunSequentially()
    {
        int calls = 0;
        var manager = new ActiveSensorManager(() => Initial, _ => Adapter,
            (_, _, _) => { calls++; return Task.FromResult(new ActiveSensorRun("OK", true, null)); });
        manager.Add(Profile()); manager.Add(Profile(ActiveSensorKind.Dns));
        Assert.True(await manager.RunDueAsync(default));
        Assert.Equal(1, calls);
        Assert.True(await manager.RunDueAsync(default));
        Assert.False(await manager.RunDueAsync(default));
        Assert.Equal(2, calls);
    }
}
