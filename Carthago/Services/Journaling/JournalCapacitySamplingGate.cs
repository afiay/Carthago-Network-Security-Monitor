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
        private readonly Func<long, double, (bool Sampled, bool Low, long Available, long Total)> _capacityReader;
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
            double minimumFreePercent, TimeSpan minimumInterval, TimeSpan? maximumInterval = null,
            Func<long, double, (bool Sampled, bool Low, long Available, long Total)>? capacityReader = null)
        {
            _journal = journal ?? throw new ArgumentNullException(nameof(journal));
            // The default remains journal-owned OS sampling. Injection is for deterministic
            // tests; callers must not treat externally supplied readings as trusted events.
            _capacityReader = capacityReader ?? ((bytes, percent) =>
            {
                var sampled = _journal.TryEvaluateConfiguredVolumeCapacity(bytes, percent,
                    out var low, out var available, out var total);
                return (sampled, low, available, total);
            });
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
                    maintenance || (_previousUtc.HasValue && sampledAtUtc < _previousUtc.Value))
                {
                    ResetCore();
                    return false;
                }

                // A duplicate scheduler tick is not a new measurement and must not
                // re-arm an already confirmed low-space episode.
                if (_previousUtc.HasValue && sampledAtUtc == _previousUtc.Value)
                    return false;

                if (_previousUtc.HasValue)
                {
                    var elapsed = sampledAtUtc - _previousUtc.Value;
                    if (elapsed < _minimumInterval)
                        return false;
                    if (elapsed > _maximumInterval)
                        ResetCore();
                }

                var sample = _capacityReader(_minimumFreeBytes, _minimumFreePercent);
                if (!sample.Sampled || sample.Total <= 0 || sample.Available < 0 ||
                    sample.Available > sample.Total)
                {
                    ResetCore();
                    return false;
                }
                // Never let a reader's claimed classification override the actual
                // capacity measurements and the configured two-threshold policy.
                // Inconsistent producer output is unknown, not a low-space event.
                var expectedLow = sample.Available < _minimumFreeBytes &&
                    (double)sample.Available / sample.Total * 100 < _minimumFreePercent;
                if (sample.Low != expectedLow)
                {
                    ResetCore();
                    return false;
                }
                availableBytes = sample.Available;
                totalBytes = sample.Total;
                var low = expectedLow;

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
