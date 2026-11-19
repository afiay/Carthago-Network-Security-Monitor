// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Services
{
    /// <summary>
    /// Lifecycle-owned journal capacity sampler. This is health telemetry, not a
    /// packet detection or an R531 alert. No externally supplied capacity reader
    /// is accepted on the production path.
    /// </summary>
    internal sealed class JournalCapacityMonitor
    {
        private readonly JournalCapacitySamplingGate _gate;
        private readonly TimeSpan _interval;
        private readonly Func<bool> _maintenance;
        private readonly Action<DateTime, long, long> _confirmedLow;

        internal JournalCapacityMonitor(
            DetectionJournal journal,
            long minimumFreeBytes,
            double minimumFreePercent,
            TimeSpan interval,
            Func<bool> maintenance,
            Action<DateTime, long, long> confirmedLow)
        {
            if (interval <= TimeSpan.Zero)
                throw new ArgumentOutOfRangeException(nameof(interval));
            _maintenance = maintenance ?? throw new ArgumentNullException(nameof(maintenance));
            _confirmedLow = confirmedLow ?? throw new ArgumentNullException(nameof(confirmedLow));
            _interval = interval;
            _gate = new JournalCapacitySamplingGate(journal, minimumFreeBytes,
                minimumFreePercent, interval);
        }

        /// <summary>
        /// Run only under an application-owned cancellation token. A failed
        /// maintenance-policy read cannot be interpreted as non-maintenance.
        /// The callback is an internal handoff prerequisite, not RuleEngine
        /// admission; the caller must still enforce provenance and policy.
        /// </summary>
        internal async Task RunAsync(CancellationToken cancellationToken)
        {
            using var timer = new PeriodicTimer(_interval);
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                bool maintenance;
                try { maintenance = _maintenance(); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _gate.Reset();
                    continue;
                }

                var utc = DateTime.UtcNow;
                if (_gate.TrySample(utc, maintenance, out var confirmed,
                    out var available, out var total) && confirmed)
                {
                    _confirmedLow(utc, available, total);
                }
            }
        }
    }
}
