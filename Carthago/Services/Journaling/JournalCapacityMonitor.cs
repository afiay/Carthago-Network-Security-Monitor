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
        private int _running;
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
            // A single monitor instance must never run multiple independent polling
            // loops: overlapping loops could consume one another's confirmation
            // state and misattribute an episode to the wrong application owner.
            if (Interlocked.CompareExchange(ref _running, 1, 0) != 0)
                throw new InvalidOperationException("Journal capacity monitor is already running.");
            try
            {
                // Timer construction belongs inside the ownership cleanup boundary.
                // A construction failure must not permanently strand _running at 1.
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

                // Shutdown can race with the maintenance provider. Never sample or
                // deliver a health confirmation after the owner has cancelled.
                cancellationToken.ThrowIfCancellationRequested();
                var utc = DateTime.UtcNow;
                if (_gate.TrySample(utc, maintenance, out var confirmed,
                    out var available, out var total) && confirmed)
                {
                    // A failed handoff must not retain a confirmed episode as if
                    // the downstream owner had accepted it. Fail visibly; never
                    // convert a callback failure into a detection event.
                    cancellationToken.ThrowIfCancellationRequested();
                    try { _confirmedLow(utc, available, total); }
                    catch
                    {
                        _gate.Reset();
                        throw;
                    }
                }
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // Expected application shutdown, not a sampling failure.
            }
            finally
            {
                _gate.Reset();
                Volatile.Write(ref _running, 0);
            }
        }
    }
}
