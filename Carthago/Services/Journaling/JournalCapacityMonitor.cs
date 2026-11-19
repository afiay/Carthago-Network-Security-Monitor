// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;

namespace Carthago.Services
{
    /// <summary>
    /// Lifecycle-owned journal capacity sampler. It reads only the configured
    /// DetectionJournal volume and hands off immutable, owner-bound evidence.
    /// </summary>
    internal sealed class JournalCapacityMonitor
    {
        private readonly DetectionJournal _journal;
        private readonly JournalCapacitySamplingGate _gate;
        private readonly long _minimumFreeBytes;
        private readonly double _minimumFreePercent;
        private int _running;
        private readonly TimeSpan _interval;
        private readonly Func<bool> _maintenance;
        private readonly Action<JournalCapacityHealthEvidence> _confirmedLow;

        internal JournalCapacityMonitor(
            DetectionJournal journal,
            long minimumFreeBytes,
            double minimumFreePercent,
            TimeSpan interval,
            Func<bool> maintenance,
            Action<JournalCapacityHealthEvidence> confirmedLow)
        {
            _journal = journal ?? throw new ArgumentNullException(nameof(journal));
            if (interval <= TimeSpan.Zero)
                throw new ArgumentOutOfRangeException(nameof(interval));
            _maintenance = maintenance ?? throw new ArgumentNullException(nameof(maintenance));
            _confirmedLow = confirmedLow ?? throw new ArgumentNullException(nameof(confirmedLow));
            _minimumFreeBytes = minimumFreeBytes;
            _minimumFreePercent = minimumFreePercent;
            _interval = interval;
            _gate = new JournalCapacitySamplingGate(
                _journal, minimumFreeBytes, minimumFreePercent, interval);
        }

        /// <summary>
        /// Run only under an application-owned cancellation token. Missing or
        /// failing maintenance policy is fail-closed. The handoff is typed and
        /// bound to the configured journal path; it is not a packet record.
        /// </summary>
        internal async Task RunAsync(CancellationToken cancellationToken)
        {
            if (Interlocked.CompareExchange(ref _running, 1, 0) != 0)
                throw new InvalidOperationException("Journal capacity monitor is already running.");

            try
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

                    cancellationToken.ThrowIfCancellationRequested();
                    var utc = DateTime.UtcNow;
                    if (!_gate.TrySample(utc, maintenance, out var confirmed,
                        out var available, out var total) || !confirmed)
                        continue;

                    cancellationToken.ThrowIfCancellationRequested();
                    var evidence = _journal.CreateConfirmedLowCapacityEvidence(
                        utc, available, total, _minimumFreeBytes, _minimumFreePercent);
                    if (evidence is null)
                    {
                        _gate.Reset();
                        continue;
                    }

                    try { _confirmedLow(evidence); }
                    catch
                    {
                        _gate.Reset();
                        throw;
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
