// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Services
{
    /// <summary>Observes a long-running capture task without blocking its caller.</summary>
    public static class CaptureTaskFailureObserver
    {
        public static void Observe(Task captureTask, Action<Exception> onFailure)
        {
            if (captureTask == null) throw new ArgumentNullException(nameof(captureTask));
            if (onFailure == null) throw new ArgumentNullException(nameof(onFailure));

            _ = captureTask.ContinueWith(task =>
            {
                var error = task.Exception?.GetBaseException();
                if (error != null) onFailure(error);
            }, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);
        }
    }
}
