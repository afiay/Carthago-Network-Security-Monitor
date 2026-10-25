// SPDX-License-Identifier: MIT
using System;
using System.Threading;

namespace Carthago.Services;

/// <summary>
/// Prevents dashboard work already queued on the dispatcher from running during shutdown.
/// </summary>
internal sealed class DashboardCallbackGate
{
    private int _closed;

    public bool IsOpen => Volatile.Read(ref _closed) == 0;

    public void Close() => Interlocked.Exchange(ref _closed, 1);

    public void RunIfOpen(Action callback)
    {
        ArgumentNullException.ThrowIfNull(callback);
        if (IsOpen)
            callback();
    }
}
