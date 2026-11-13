// SPDX-License-Identifier: MIT
using Carthago.Contracts;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class CaptureReservationTests
{
    private static string Name() => @"Global\Carthago.Test.Capture." + Guid.NewGuid().ToString("N");

    [Fact]
    public void ExclusiveUntilReleased()
    {
        if (!OperatingSystem.IsWindows()) return;
        string name = Name();
        using (var first = WindowsCaptureReservation.AcquireNamed(name))
            Assert.Throws<InvalidOperationException>(() => WindowsCaptureReservation.AcquireNamed(name));
        using var next = WindowsCaptureReservation.AcquireNamed(name);
    }

    [Fact]
    public async Task ReleaseDoesNotRequireAcquiringThread()
    {
        if (!OperatingSystem.IsWindows()) return;
        string name = Name();
        var first = WindowsCaptureReservation.AcquireNamed(name);
        await Task.Run(first.Dispose);
        using var next = WindowsCaptureReservation.AcquireNamed(name);
    }

    [Fact]
    public void QuarantinedHandleRemainsReservedEvenAfterDispose()
    {
        if (!OperatingSystem.IsWindows()) return;
        string name = Name();
        var lease = WindowsCaptureReservation.AcquireNamed(name);
        lease.Quarantine();
        lease.Dispose();
        Assert.Throws<InvalidOperationException>(() => WindowsCaptureReservation.AcquireNamed(name));
    }

    [Fact]
    public async Task ConcurrentContendersHaveOnlyOneWinner()
    {
        if (!OperatingSystem.IsWindows()) return;
        string name = Name();
        var leases = new System.Collections.Concurrent.ConcurrentBag<WindowsCaptureReservation>();
        try
        {
            await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() =>
            {
                try { leases.Add(WindowsCaptureReservation.AcquireNamed(name)); }
                catch (InvalidOperationException) { }
            })));
            Assert.Single(leases);
        }
        finally { foreach (var lease in leases) lease.Dispose(); }
        using var next = WindowsCaptureReservation.AcquireNamed(name);
    }
}
