// SPDX-License-Identifier: MIT
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Contracts;
using Carthago.Services;
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

public sealed class ActiveSchedulerOwnershipTests
{
    private static string Name() => @"Global\Carthago.Test.ActiveScheduler." + Guid.NewGuid().ToString("N");
    private static readonly Guid AdapterId = Guid.Parse("02702701-1234-4321-9999-000000000001");
    private static readonly LocalLanInterface Adapter = new("lab", IPAddress.Parse("192.168.50.10"), IPAddress.Parse("255.255.255.0"));
    private static ActiveSensorProfile Profile() => ActiveSensorProfile.Create(AdapterId, Adapter,
        IPAddress.Parse("192.168.50.11"), ActiveSensorKind.Tcp, "", 0, TimeSpan.FromMinutes(5), false);

    [Fact]
    public async Task NativeReservationIsExclusiveAndReleaseIsNotThreadAffine()
    {
        string name = Name();
        using var first = WindowsActiveSchedulerReservation.AcquireNamed(name);
        Assert.Throws<InvalidOperationException>(() => WindowsActiveSchedulerReservation.AcquireNamed(name));
        await Task.Run(first.Dispose);
        using var next = WindowsActiveSchedulerReservation.AcquireNamed(name);
    }

    [Fact]
    public async Task NativeConcurrentContendersHaveOneWinner()
    {
        string name = Name();
        var leases = new ConcurrentBag<IDisposable>();
        try
        {
            await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => Task.Run(() =>
            {
                try { leases.Add(WindowsActiveSchedulerReservation.AcquireNamed(name)); }
                catch (InvalidOperationException) { }
            })));
            Assert.Single(leases);
        }
        finally { foreach (var lease in leases) lease.Dispose(); }
        using var next = WindowsActiveSchedulerReservation.AcquireNamed(name);
    }

    [Fact]
    public async Task ContendedLoopDoesNotProbeAndCanRetryAfterRelease()
    {
        string name = Name();
        int calls = 0;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var manager = new ActiveSensorManager(resolve: _ => Adapter, probe: (_, _, _) =>
        {
            calls++; cts.Cancel(); return Task.FromResult(new ActiveSensorRun("OK", true, null));
        }, acquireReservation: () => WindowsActiveSchedulerReservation.AcquireNamed(name));
        manager.Add(Profile());
        using (var owner = WindowsActiveSchedulerReservation.AcquireNamed(name))
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => manager.RunAsync(cts.Token));
            Assert.Equal(0, calls);
            Assert.False(manager.HasReservation);
            Assert.False(Assert.Single(manager.Snapshot()).Running);
        }
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => manager.RunAsync(cts.Token));
        Assert.Equal(1, calls);
        Assert.False(manager.HasReservation);
        using var next = WindowsActiveSchedulerReservation.AcquireNamed(name);
    }

    [Fact]
    public async Task ReservationRemainsHeldUntilProbeCleanupCompletes()
    {
        string name = Name();
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancelled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var cleanup = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var manager = new ActiveSensorManager(resolve: _ => Adapter, probe: async (_, _, token) =>
        {
            entered.TrySetResult(true);
            try { await Task.Delay(Timeout.Infinite, token); }
            finally
            {
                cancelled.TrySetResult(true);
                await cleanup.Task.WaitAsync(TimeSpan.FromSeconds(10));
            }
            return new ActiveSensorRun("OK", true, null);
        }, acquireReservation: () => WindowsActiveSchedulerReservation.AcquireNamed(name));
        var p = Profile();
        manager.Add(p);
        var running = manager.RunAsync(cts.Token);
        try
        {
            await entered.Task.WaitAsync(cts.Token);
            Assert.True(manager.HasReservation);
            Assert.Throws<InvalidOperationException>(() => WindowsActiveSchedulerReservation.AcquireNamed(name));
            await Assert.ThrowsAsync<InvalidOperationException>(() => manager.RunAsync(default));
            Assert.False(await manager.RunDueAsync(default));
            Assert.False(manager.Remove(p.Id));
            cts.Cancel();
            await cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.False(running.IsCompleted);
            Assert.Throws<InvalidOperationException>(() => WindowsActiveSchedulerReservation.AcquireNamed(name));
        }
        finally { cts.Cancel(); cleanup.TrySetResult(true); }
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.False(manager.HasReservation);
        Assert.False(Assert.Single(manager.Snapshot()).Running);
        using var next = WindowsActiveSchedulerReservation.AcquireNamed(name);
    }

    [Fact]
    public async Task PreCancelledOrEmptyLoopDoesNotAcquireAndProductionTickIsRejected()
    {
        int acquired = 0;
        var manager = new ActiveSensorManager(acquireReservation: () =>
        { acquired++; throw new InvalidOperationException("Unexpected acquisition"); });
        await Assert.ThrowsAsync<InvalidOperationException>(() => manager.RunAsync(default));
        manager.Add(Profile());
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => manager.RunAsync(cts.Token));
        Assert.Throws<InvalidOperationException>(() => { _ = manager.RunDueAsync(default); });
        Assert.Equal(0, acquired);
    }
}
