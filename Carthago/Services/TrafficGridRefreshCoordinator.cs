using System;

namespace Carthago.Services
{
    /// <summary>
    /// UI-thread-only cadence gate for Live Traffic collection notifications.
    /// Capture batches and retained rows remain immediate and unthrottled.
    /// </summary>
    public sealed class TrafficGridRefreshCoordinator
    {
        public static readonly TimeSpan RefreshInterval = TimeSpan.FromMilliseconds(250);

        private bool _dirty;
        private bool _timerScheduled;
        private bool _stopped;

        /// <summary>Only the first visible request schedules a timer.</summary>
        public bool Request(bool visible)
        {
            if (_stopped)
                return false;

            _dirty = true;
            if (!visible || _timerScheduled)
                return false;

            _timerScheduled = true;
            return true;
        }

        /// <summary>Returns true when a scheduled timer has a visible update to publish.</summary>
        public bool OnTimer(bool visible)
        {
            if (!_timerScheduled)
                return false;

            _timerScheduled = false;
            if (_stopped || !visible || !_dirty)
                return false;

            _dirty = false;
            return true;
        }

        /// <summary>Cancel a pending visual timer, preserving changed rows.</summary>
        public void Hide() => _timerScheduled = false;

        /// <summary>Navigation publishes one current snapshot immediately.</summary>
        public bool Show()
        {
            if (_stopped)
                return false;

            _timerScheduled = false;
            _dirty = false;
            return true;
        }

        public void Stop()
        {
            _stopped = true;
            _timerScheduled = false;
            _dirty = false;
        }
    }
}
