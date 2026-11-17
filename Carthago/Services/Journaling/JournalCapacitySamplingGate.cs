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
        private readonly long _minimumFreeBytes;
        private readonly double _minimumFreePercent;
        private readonly TimeSpan _minimumInterval;
        private DateTime? _previousUtc;
        private int _consecutiveLow;

        public JournalCapacitySamplingGate(
            DetectionJournal journal, long minimumFreeBytes,
            double minimumFreePercent, TimeSpan minimumInterval)
        {
            _journal = journal ?? throw new ArgumentNullException(nameof(journal));
            if (minimumFreeBytes <= 0 || minimumFreePercent <= 0 ||
                minimumFreePercent > 100 || double.IsNaN(minimumFreePercent) ||
                double.IsInfinity(minimumFreePercent) || minimumInterval <= TimeSpan.Zero)
                throw new ArgumentOutOfRangeException(nameof(minimumFreeBytes),
                    "Valid byte, percent and sampling-interval policy is required.");
            _minimumFreeBytes = minimumFreeBytes;
            _minimumFreePercent = minimumFreePercent;
            _minimumInterval = minimumInterval;
        }

        /// <summary>
        /// True only when a fresh, non-maintenance OS sample was obtained.
        /// confirmedLow requires two consecutive low readings separated by the
        /// configured interval. Unknown/maintenance samples reset the gate.
        /// </summary>
        public bool TrySample(DateTime sampledAtUtc, bool maintenance,
            out bool confirmedLow, out long availableBytes, out long totalBytes)
        {
            confirmedLow = false;
            availableBytes = 0;
            totalBytes = 0;
            if (sampledAtUtc.Kind != DateTimeKind.Utc || sampledAtUtc == default ||
                maintenance || (_previousUtc.HasValue && sampledAtUtc <= _previousUtc.Value))
            {
                Reset();
                return false;
            }

            if (_previousUtc.HasValue && sampledAtUtc - _previousUtc.Value < _minimumInterval)
                return false;

            if (!_journal.TryEvaluateConfiguredVolumeCapacity(
                _minimumFreeBytes, _minimumFreePercent,
                out var low, out availableBytes, out totalBytes))
            {
                Reset();
                return false;
            }

            _previousUtc = sampledAtUtc;
            _consecutiveLow = low ? Math.Min(2, _consecutiveLow + 1) : 0;
            confirmedLow = _consecutiveLow == 2;
            return true;
        }

        public void Reset()
        {
            _previousUtc = null;
            _consecutiveLow = 0;
        }
    }
}
