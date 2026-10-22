// SPDX-License-Identifier: MIT
// File: Analytics/Services/UserBehaviorEngine.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;

namespace Carthago.Analytics.Services
{
    /// <summary>
    /// Tiny UBA-ish baseline: track recent event counts per "actor" (fall back to SourceIp).
    /// Flags an actor as an outlier when its 5-min event count exceeds 3× its trailing median.
    /// </summary>
    public sealed class UserBehaviorEngine
    {
        private readonly TimeSpan _window = TimeSpan.FromMinutes(5);
        private readonly Dictionary<string, List<DateTime>> _byActor = new(StringComparer.Ordinal);

        private static string ActorOf(DetectionEvent e)
            => !string.IsNullOrWhiteSpace(e.SourceIp) ? e.SourceIp : "unknown";

        public void OnEvent(DetectionEvent e)
        {
            var actor = ActorOf(e);
            if (!_byActor.TryGetValue(actor, out var list))
                _byActor[actor] = list = new List<DateTime>(64);

            var now = e.Timestamp; // use existing property
            list.Add(now);

            // drop outside window
            var cutoff = now - _window;
            var idx = list.FindIndex(dt => dt >= cutoff);
            if (idx > 0) list.RemoveRange(0, idx);
        }

        public IEnumerable<(string actor, int recent, double median)> GetPotentialOutliers()
        {
            foreach (var kv in _byActor)
            {
                var actor = kv.Key;
                var count = kv.Value.Count;
                var median = Median(_byActor.Values.Select(v => (double)v.Count));
                if (median <= 0) median = 1;
                if (count >= 3 && count > 3 * median)
                    yield return (actor, count, median);
            }
        }

        private static double Median(IEnumerable<double> data)
        {
            var a = data.OrderBy(x => x).ToArray();
            if (a.Length == 0) return 0;
            int mid = a.Length / 2;
            return (a.Length % 2 == 1) ? a[mid] : (a[mid - 1] + a[mid]) / 2.0;
        }
    }
}
