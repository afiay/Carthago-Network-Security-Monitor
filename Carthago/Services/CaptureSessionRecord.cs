// SPDX-License-Identifier: MIT
using System;
using System.Threading;

namespace Carthago.Services
{
    /// <summary>A queued record retains the cancellation state of its originating capture.</summary>
    public sealed record CaptureSessionRecord<T>(T Value, CancellationToken SessionToken)
    {
        public bool TryDeliver(Action<T> deliver)
        {
            if (deliver == null) throw new ArgumentNullException(nameof(deliver));
            if (SessionToken.IsCancellationRequested) return false;
            deliver(Value);
            return true;
        }
    }
}
