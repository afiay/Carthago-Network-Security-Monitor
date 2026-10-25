// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services
{
    public enum CaptureFlowState { Stopped, Starting, Idle, Flowing, Stalled }

    public sealed record CaptureFlowAssessment(CaptureFlowState State, string Reason);

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

        public static CaptureFlowAssessment Assess(
            bool running, DateTimeOffset startedAt, long captured, long displayed, long dropped,
            DateTimeOffset? lastCapturedAt, DateTimeOffset? lastDisplayedAt, DateTimeOffset now)
        {
            var state = Evaluate(running, startedAt, captured, displayed, lastCapturedAt, lastDisplayedAt, now);
            var reason = state switch
            {
                CaptureFlowState.Stopped => "CAPTURE_STOPPED",
                CaptureFlowState.Starting => "CAPTURE_STARTING",
                CaptureFlowState.Idle => "WAITING_FOR_TRAFFIC",
                CaptureFlowState.Stalled => "UI_DELIVERY_STALLED",
                _ when dropped > 0 => "UI_QUEUE_DROPS",
                _ => "CAPTURE_AND_UI_FLOWING"
            };
            return new CaptureFlowAssessment(state, reason);
        }
    }
}
