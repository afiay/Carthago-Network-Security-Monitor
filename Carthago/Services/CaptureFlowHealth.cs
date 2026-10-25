// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services
{
    public enum CaptureFlowState { Stopped, Starting, Idle, Flowing, Stalled }

    /// <summary>
    /// Distinguishes a quiet capture from one receiving events that do not reach the UI.
    /// This is diagnostic only: a stalled state does not automatically restart capture.
    /// </summary>
    public static class CaptureFlowHealth
    {
        private static readonly TimeSpan GracePeriod = TimeSpan.FromSeconds(10);

        public static CaptureFlowState Evaluate(
            bool running, DateTimeOffset startedAt, long captured, long displayed,
            DateTimeOffset? lastCapturedAt, DateTimeOffset? lastDisplayedAt, DateTimeOffset now)
        {
            if (!running) return CaptureFlowState.Stopped;
            if (now - startedAt < GracePeriod) return CaptureFlowState.Starting;
            if (captured <= 0 || !lastCapturedAt.HasValue || now - lastCapturedAt.Value > GracePeriod)
                return CaptureFlowState.Idle;

            if (displayed <= 0 || !lastDisplayedAt.HasValue || now - lastDisplayedAt.Value >= GracePeriod)
                return CaptureFlowState.Stalled;

            return CaptureFlowState.Flowing;
        }
    }
}
