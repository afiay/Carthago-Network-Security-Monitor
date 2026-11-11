using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;

namespace Carthago.Services
{
    public sealed class UiOperationTimingCounter
    {
        private long _count;
        private long _totalMilliseconds;
        private long _maxMilliseconds;

        public void RecordMilliseconds(long elapsed)
        {
            elapsed = Math.Max(0, elapsed);
            Interlocked.Increment(ref _count);
            Interlocked.Add(ref _totalMilliseconds, elapsed);
            long previous;
            do
            {
                previous = Interlocked.Read(ref _maxMilliseconds);
                if (elapsed <= previous) return;
            } while (Interlocked.CompareExchange(ref _maxMilliseconds, elapsed, previous) != previous);
        }

        public (long Count, long TotalMilliseconds, long MaxMilliseconds) Snapshot()
            => (Interlocked.Read(ref _count), Interlocked.Read(ref _totalMilliseconds), Interlocked.Read(ref _maxMilliseconds));
    }

    /// <summary>Opt-in, aggregate-only UI operation timings; no packet or alert content.</summary>
    public static class UiOperationProfiler
    {
        private static readonly string? PathToLog = Environment.GetEnvironmentVariable("CARTHAGO_UI_PROFILE_PATH");
        private static readonly ConcurrentDictionary<string, UiOperationTimingCounter> Counters = new(StringComparer.Ordinal);
        private static readonly Timer? FlushTimer = string.IsNullOrWhiteSpace(PathToLog)
            ? null : new Timer(_ => Flush(), null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));
        private static int _flushing;

        public static void Measure(string name, Action action)
        {
            if (string.IsNullOrWhiteSpace(PathToLog)) { action(); return; }
            var sw = Stopwatch.StartNew();
            try { action(); }
            finally
            {
                sw.Stop();
                Counters.GetOrAdd(name, _ => new UiOperationTimingCounter()).RecordMilliseconds(sw.ElapsedMilliseconds);
            }
        }

        private static void Flush()
        {
            if (string.IsNullOrWhiteSpace(PathToLog) || Interlocked.Exchange(ref _flushing, 1) != 0) return;
            try
            {
                var folder = System.IO.Path.GetDirectoryName(PathToLog);
                if (!string.IsNullOrWhiteSpace(folder)) Directory.CreateDirectory(folder);
                if (!File.Exists(PathToLog))
                    File.AppendAllText(PathToLog, "timestampUtc,operation,count,totalMs,maxMs" + Environment.NewLine);
                var stamp = DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture);
                var lines = Counters.OrderBy(x => x.Key).Select(entry =>
                {
                    var s = entry.Value.Snapshot();
                    return string.Join(",", stamp, entry.Key,
                        s.Count.ToString(CultureInfo.InvariantCulture),
                        s.TotalMilliseconds.ToString(CultureInfo.InvariantCulture),
                        s.MaxMilliseconds.ToString(CultureInfo.InvariantCulture));
                });
                File.AppendAllText(PathToLog, string.Join(Environment.NewLine, lines) + Environment.NewLine);
            }
            catch (Exception) { /* optional diagnostics cannot affect capture */ }
            finally { Volatile.Write(ref _flushing, 0); }
        }
    }
}
