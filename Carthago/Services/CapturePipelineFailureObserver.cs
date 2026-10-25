// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;

namespace Carthago.Services
{
    /// <summary>Reports failures of either the capture producer or its record reader.</summary>
    public static class CapturePipelineFailureObserver
    {
        public static void Observe(Task sourceTask, Task readerTask, Action<string, Exception> onFailure)
        {
            if (sourceTask == null) throw new ArgumentNullException(nameof(sourceTask));
            if (readerTask == null) throw new ArgumentNullException(nameof(readerTask));
            if (onFailure == null) throw new ArgumentNullException(nameof(onFailure));

            CaptureTaskFailureObserver.Observe(sourceTask, ex => onFailure("source", ex));
            CaptureTaskFailureObserver.Observe(readerTask, ex => onFailure("reader", ex));
        }
    }
}
