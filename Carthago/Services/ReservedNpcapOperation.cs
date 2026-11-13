// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Contracts;

namespace Carthago.Services;

/// <summary>Exclusive short-lived Npcap operation. If native cleanup is
/// uncertain, keep the machine-wide reservation until process exit.</summary>
internal static class ReservedNpcapOperation
{
    internal static async Task RunAsync(Func<Task> operation, Action cleanup,
        CancellationToken token, Func<WindowsCaptureReservation>? acquire = null)
    {
        token.ThrowIfCancellationRequested();
        using var reservation = (acquire ?? WindowsCaptureReservation.Acquire)();
        try
        {
            token.ThrowIfCancellationRequested();
            await operation().ConfigureAwait(false);
        }
        finally
        {
            try { cleanup(); }
            catch
            {
                reservation.Quarantine();
                throw;
            }
        }
    }

    // Attempt all cleanup steps even if an earlier native operation fails.
    internal static void Cleanup(Action stop, Action close, Action detach)
    {
        try { stop(); }
        finally
        {
            try { close(); }
            finally { detach(); }
        }
    }
}
