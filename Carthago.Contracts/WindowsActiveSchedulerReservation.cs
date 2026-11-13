// SPDX-License-Identifier: MIT
using System.Runtime.Versioning;

namespace Carthago.Contracts;

/// <summary>Machine-wide cooperative ownership of the scheduled active-probe
/// loop. Separate from capture ownership; no thread-affine mutex acquisition.</summary>
[SupportedOSPlatform("windows")]
public static class WindowsActiveSchedulerReservation
{
    public const string DefaultName = @"Global\Carthago.ActiveScheduler.Reservation.v1";

    public static IDisposable Acquire() => AcquireNamed(DefaultName);

    // Isolated qualification only; production uses the fixed name.
    public static IDisposable AcquireNamed(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (!name.StartsWith(@"Global\Carthago.Test.ActiveScheduler.", StringComparison.Ordinal) &&
            !string.Equals(name, DefaultName, StringComparison.Ordinal))
            throw new ArgumentException("Invalid active scheduler reservation name.", nameof(name));
        try
        {
            return WindowsCaptureReservation.AcquireNamed(name);
        }
        catch (InvalidOperationException ex)
        {
            throw new InvalidOperationException("Another Carthago active scheduler owns the machine-wide reservation. Stop it before starting another.", ex);
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            throw new InvalidOperationException("Machine-wide active scheduler reservation unavailable. No probes started.", ex);
        }
    }
}
