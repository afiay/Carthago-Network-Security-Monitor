// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Contracts;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public sealed class ActiveNpcapCoordinationTests
{
    private static string Name() => @"Global\Carthago.Test.Capture." + Guid.NewGuid().ToString("N");

    [Fact]
    public async Task ContentionPreventsOpenAndCleanupOfUnownedDevice()
    {
        string name = Name();
        using var owner = WindowsCaptureReservation.AcquireNamed(name);
        int operations = 0, cleanups = 0;
        await Assert.ThrowsAsync<CaptureReservationUnavailableException>(() => ReservedNpcapOperation.RunAsync(
            () => { operations++; return Task.CompletedTask; }, () => cleanups++, default,
            () => WindowsCaptureReservation.AcquireNamed(name)));
        Assert.Equal(0, operations);
        Assert.Equal(0, cleanups);
    }

    [Fact]
    public async Task ReservationHeldAcrossOperationAndCleanupThenReleased()
    {
        string name = Name();
        var sequence = new List<string>();
        await ReservedNpcapOperation.RunAsync(async () =>
        {
            sequence.Add("open");
            await Task.Yield();
            Assert.Throws<InvalidOperationException>(() => WindowsCaptureReservation.AcquireNamed(name));
        }, () =>
        {
            sequence.Add("close");
            Assert.Throws<InvalidOperationException>(() => WindowsCaptureReservation.AcquireNamed(name));
        }, default, () => WindowsCaptureReservation.AcquireNamed(name));
        Assert.Equal(new[] { "open", "close" }, sequence);
        using var next = WindowsCaptureReservation.AcquireNamed(name);
    }

    [Fact]
    public async Task CancellationAwaitsCleanupBeforeRelease()
    {
        string name = Name();
        using var cancel = new CancellationTokenSource();
        bool cleaned = false;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ReservedNpcapOperation.RunAsync(() =>
        {
            cancel.Cancel();
            cancel.Token.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }, () => { cleaned = true; Assert.Throws<InvalidOperationException>(() => WindowsCaptureReservation.AcquireNamed(name)); },
            cancel.Token, () => WindowsCaptureReservation.AcquireNamed(name)));
        Assert.True(cleaned);
        using var next = WindowsCaptureReservation.AcquireNamed(name);
    }

    [Fact]
    public async Task PartialOpenFailureStillCleansUpAndReleases()
    {
        string name = Name();
        bool cleaned = false;
        await Assert.ThrowsAsync<InvalidOperationException>(() => ReservedNpcapOperation.RunAsync(
            () => throw new InvalidOperationException("Injected open failure"),
            () => cleaned = true, default, () => WindowsCaptureReservation.AcquireNamed(name)));
        Assert.True(cleaned);
        using var next = WindowsCaptureReservation.AcquireNamed(name);
    }

    [Theory]
    [InlineData("stop")]
    [InlineData("close")]
    [InlineData("detach")]
    public async Task CleanupFailureAttemptsAllStepsAndQuarantines(string failure)
    {
        string name = Name();
        var steps = new List<string>();
        void Step(string step)
        {
            steps.Add(step);
            if (step == failure) throw new InvalidOperationException("Injected cleanup failure");
        }
        await Assert.ThrowsAsync<InvalidOperationException>(() => ReservedNpcapOperation.RunAsync(
            () => Task.CompletedTask, () => ReservedNpcapOperation.Cleanup(
                () => Step("stop"), () => Step("close"), () => Step("detach")),
            default, () => WindowsCaptureReservation.AcquireNamed(name)));
        Assert.Equal(new[] { "stop", "close", "detach" }, steps);
        Assert.Throws<InvalidOperationException>(() => WindowsCaptureReservation.AcquireNamed(name));
    }

    [Fact]
    public async Task PreCancelledOperationDoesNotAcquire()
    {
        using var cancel = new CancellationTokenSource();
        cancel.Cancel();
        int acquired = 0;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ReservedNpcapOperation.RunAsync(
            () => Task.CompletedTask, () => { }, cancel.Token,
            () => { acquired++; throw new InvalidOperationException("Unexpected acquisition"); }));
        Assert.Equal(0, acquired);
    }
}
