// SPDX-License-Identifier: MIT
using System;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;

namespace Carthago.Services
{
    /// <summary>
    /// WPF application-lifetime owner for the optional R531 local health producer.
    /// No thresholds are defaulted: the monitor starts only with explicit operator
    /// configuration and an explicit non-maintenance state.
    /// </summary>
    internal sealed class JournalCapacityMonitorHost
    {
        private readonly CancellationTokenSource _cancellation = new();
        private readonly Task _runTask;
        private int _stopped;

        private JournalCapacityMonitorHost(JournalCapacityMonitor monitor)
        {
            _runTask = Task.Run(async () =>
            {
                try
                {
                    await monitor.RunAsync(_cancellation.Token).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    Console.Error.WriteLine(
                        "[R531] Journal capacity monitor stopped: " + ex.GetType().Name);
                }
            });
        }

        internal static JournalCapacityMonitorHost? TryStartFromEnvironment()
        {
            if (!bool.TryParse(
                    Environment.GetEnvironmentVariable("CARTHAGO_JOURNAL_HEALTH_MONITOR_ENABLED"),
                    out var enabled) || !enabled)
                return null;

            if (!TryReadConfiguration(out var minimumFreeBytes,
                    out var minimumFreePercent, out var interval))
            {
                Console.Error.WriteLine(
                    "[R531] Monitor not started: explicit valid byte, percent and interval settings are required.");
                return null;
            }

            if (IsMaintenanceActive())
            {
                Console.Error.WriteLine(
                    "[R531] Monitor not started: CARTHAGO_JOURNAL_MAINTENANCE must be explicitly false.");
                return null;
            }

            // Resolve the same owner used by RuleEngine persistence. The monitor
            // must never sample one journal volume while detections are written to another.
            var journal = RuleEngine.GetActiveDetectionJournalForHealthMonitor();
            var monitor = new JournalCapacityMonitor(
                journal,
                minimumFreeBytes,
                minimumFreePercent,
                interval,
                IsMaintenanceActive,
                evidence =>
                {
                    var detections = RuleEngine.EvaluateJournalCapacityHealth(
                        journal, evidence, Sensitivity.Balanced);
                    foreach (var detection in detections)
                    {
                        if (detection.DeliveryStatus == DetectionDeliveryStatus.FailedToPersist)
                        {
                            // The low-space event was evaluated, but the same-volume
                            // journal could not durably store it. Do not claim persistence.
                            Console.Error.WriteLine(
                                "[R531] Low journal capacity matched, but detection persistence failed.");
                        }
                    }
                });

            Console.WriteLine("[R531] Configured journal capacity monitor started.");
            return new JournalCapacityMonitorHost(monitor);
        }

        internal void Stop()
        {
            if (Interlocked.Exchange(ref _stopped, 1) != 0)
                return;

            _cancellation.Cancel();
            try { _runTask.GetAwaiter().GetResult(); }
            finally { _cancellation.Dispose(); }
        }

        private static bool IsMaintenanceActive()
            => !string.Equals(
                Environment.GetEnvironmentVariable("CARTHAGO_JOURNAL_MAINTENANCE"),
                "false",
                StringComparison.OrdinalIgnoreCase);

        private static bool TryReadConfiguration(
            out long minimumFreeBytes,
            out double minimumFreePercent,
            out TimeSpan interval)
        {
            minimumFreeBytes = 0;
            minimumFreePercent = 0;
            interval = default;

            if (!long.TryParse(
                    Environment.GetEnvironmentVariable("CARTHAGO_JOURNAL_MIN_FREE_BYTES"),
                    NumberStyles.None, CultureInfo.InvariantCulture, out minimumFreeBytes) ||
                minimumFreeBytes <= 0)
                return false;

            if (!double.TryParse(
                    Environment.GetEnvironmentVariable("CARTHAGO_JOURNAL_MIN_FREE_PERCENT"),
                    NumberStyles.Float, CultureInfo.InvariantCulture, out minimumFreePercent) ||
                !double.IsFinite(minimumFreePercent) ||
                minimumFreePercent <= 0 || minimumFreePercent > 100)
                return false;

            if (!int.TryParse(
                    Environment.GetEnvironmentVariable("CARTHAGO_JOURNAL_HEALTH_INTERVAL_SECONDS"),
                    NumberStyles.None, CultureInfo.InvariantCulture, out var intervalSeconds) ||
                intervalSeconds <= 0 || intervalSeconds > 86400)
                return false;

            interval = TimeSpan.FromSeconds(intervalSeconds);
            return true;
        }
    }
}
