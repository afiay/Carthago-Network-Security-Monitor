// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services
{
    /// <summary>
    /// Owned, fail-closed journal capacity sampling gate. Call only from a trusted
    /// local scheduler; this component does not publish detection events.
    /// </summary>
    public sealed class JournalCapacitySamplingGate
    {
        private readonly DetectionJournal _journal;
        private readonly object _sampleSync = new();
        private readonly long _minimumFreeBytes;
        private readonly double _minimumFreePercent;
        private readonly TimeSpan _minimumInterval;
        private readonly TimeSpan _maximumInterval;
        private DateTime? _previousUtc;
        private int _consecutiveLow;
        private bool _confirmationEmitted;

        public JournalCapacitySamplingGate(
            DetectionJournal journal, long minimumFreeBytes,
            double minimumFreePercent, TimeSpan minimumInterval, TimeSpan? maximumInterval = null)
        {
            _journal = journal ?? throw new ArgumentNullException(nameof(journal));
            if (minimumFreeBytes <= 0 || minimumFreePercent <= 0 ||
                minimumFreePercent > 100 || double.IsNaN(minimumFreePercent) ||
                double.IsInfinity(minimumFreePercent) || minimumInterval <= TimeSpan.Zero ||
                (maximumInterval.HasValue && maximumInterval.Value < minimumInterval))
                throw new ArgumentOutOfRangeException(nameof(minimumFreeBytes),
                    "Valid byte, percent and sampling-interval policy is required.");
            _minimumFreeBytes = minimumFreeBytes;
            _minimumFreePercent = minimumFreePercent;
            _minimumInterval = minimumInterval;
            _maximumInterval = maximumInterval ?? TimeSpan.FromTicks(minimumInterval.Ticks > TimeSpan.MaxValue.Ticks / 3
                ? TimeSpan.MaxValue.Ticks : minimumInterval.Ticks * 3);
        }

        /// <summary>
        /// True only when a fresh, non-maintenance OS sample was obtained.
        /// confirmedLow requires two consecutive low readings separated by the
        /// configured interval. Unknown/maintenance samples reset the gate.
        /// </summary>
        public bool TrySample(DateTime sampledAtUtc, bool maintenance,
            out bool confirmedLow, out long availableBytes, out long totalBytes)
        {
            // The journal can be shared by GUI, CLI and service monitoring callers.
            // Serialize both OS sampling and state transitions: concurrent samples
            // must never combine into a fabricated two-reading confirmation.
            lock (_sampleSync)
            {
                confirmedLow = false;
                availableBytes = 0;
                totalBytes = 0;
                if (sampledAtUtc.Kind != DateTimeKind.Utc || sampledAtUtc == default ||
                    maintenance || (_previousUtc.HasValue && sampledAtUtc <= _previousUtc.Value))
                {
                    ResetCore();
                    return false;
                }

                if (_previousUtc.HasValue)
                {
                    var elapsed = sampledAtUtc - _previousUtc.Value;
                    if (elapsed < _minimumInterval)
                        return false;
                    if (elapsed > _maximumInterval)
                        ResetCore();
                }

                if (!_journal.TryEvaluateConfiguredVolumeCapacity(
                    _minimumFreeBytes, _minimumFreePercent,
                    out var low, out availableBytes, out totalBytes))
                {
                    ResetCore();
                    return false;
                }

                _previousUtc = sampledAtUtc;
                _consecutiveLow = low ? Math.Min(2, _consecutiveLow + 1) : 0;
                // Emit once per sustained low-space episode. A healthy sample,
                // maintenance, unknown evidence or stale cadence re-arms the gate.
                confirmedLow = _consecutiveLow == 2 && !_confirmationEmitted;
                if (confirmedLow)
                    _confirmationEmitted = true;
                if (!low)
                    _confirmationEmitted = false;
                return true;
            }
        }

        public void Reset()
        {
            lock (_sampleSync)
                ResetCore();
        }

        private void ResetCore()
        {
            _previousUtc = null;
            _consecutiveLow = 0;
            _confirmationEmitted = false;
        }
    }
}
