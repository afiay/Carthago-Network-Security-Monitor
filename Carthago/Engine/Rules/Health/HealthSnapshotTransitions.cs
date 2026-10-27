// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Engine.Rules.Health
{
    // Health snapshots are point-in-time telemetry, not ordinary packet attributes.
    // A stale or future snapshot must not manufacture a new health incident.
    internal static class HealthEvidenceGate
    {
        private static readonly TimeSpan MaximumAge = TimeSpan.FromMinutes(1);

        public static bool IsFresh(RuleEvaluationContext context)
        {
            var observedAt = context.HealthSnapshot.TimestampUtc;
            return observedAt.Kind == DateTimeKind.Utc
                && observedAt <= context.TimestampUtc
                && context.TimestampUtc - observedAt <= MaximumAge;
        }
    }

    // CaptureDropDelta is a delta since the last snapshot, not a lifetime counter.
    // Each fresh snapshot can report a distinct drop interval exactly once.
    internal sealed class HealthDeltaTransition
    {
        private readonly object _sync = new();
        private DateTime _lastObservedUtc = DateTime.MinValue;

        public bool Observe(long delta, DateTime observedAtUtc)
        {
            if (delta < 0) return false;
            lock (_sync)
            {
                if (observedAtUtc <= _lastObservedUtc) return false;
                _lastObservedUtc = observedAtUtc;
                return delta > 0;
            }
        }
    }

    // The sink, journal and reload counters are cumulative. Report an increase,
    // not the same historical failure on every packet evaluation. A decrease is
    // treated as a counter reset and becomes the new baseline without alerting.
    internal sealed class HealthCounterTransition
    {
        private readonly object _sync = new();
        private DateTime _lastObservedUtc = DateTime.MinValue;
        private long _lastCount;

        public bool Observe(long count, DateTime observedAtUtc)
        {
            if (count < 0) return false;
            lock (_sync)
            {
                if (observedAtUtc <= _lastObservedUtc) return false;
                _lastObservedUtc = observedAtUtc;
                if (count < _lastCount)
                {
                    _lastCount = count;
                    return false;
                }
                if (count == _lastCount) return false;
                _lastCount = count;
                return count > 0;
            }
        }
    }

    // A stale feed is an episode, not a new incident for every observed packet.
    // A successful fresh update rearms the detector for a later stale episode.
    internal sealed class HealthFeedStalenessTransition
    {
        private readonly object _sync = new();
        private DateTime _lastObservedUtc = DateTime.MinValue;
        private DateTime? _lastAlertedFeedUtc;
        private static readonly TimeSpan MaximumFeedAge = TimeSpan.FromHours(24);

        public bool Observe(DateTime? lastFeedUtc, DateTime observedAtUtc)
        {
            lock (_sync)
            {
                if (observedAtUtc <= _lastObservedUtc) return false;
                _lastObservedUtc = observedAtUtc;
                if (!lastFeedUtc.HasValue || lastFeedUtc.Value.Kind != DateTimeKind.Utc
                    || lastFeedUtc.Value > observedAtUtc)
                    return false;
                if (observedAtUtc - lastFeedUtc.Value <= MaximumFeedAge)
                {
                    _lastAlertedFeedUtc = null;
                    return false;
                }
                if (_lastAlertedFeedUtc == lastFeedUtc.Value) return false;
                _lastAlertedFeedUtc = lastFeedUtc.Value;
                return true;
            }
        }
    }

// A clock offset is an episode, not a new alert for every packet. Recovery
// or a sign reversal establishes a new episode; duplicate/out-of-order
// health snapshots cannot manufacture repeated incidents.
internal sealed class ClockSkewEpisodeTransition
{
    private readonly object _sync = new();
    private DateTime _lastObservedUtc = DateTime.MinValue;
    private int _activeSign;

    public bool Observe(TimeSpan skew, DateTime observedAtUtc)
    {
        lock (_sync)
        {
            if (observedAtUtc <= _lastObservedUtc) return false;
            _lastObservedUtc = observedAtUtc;
            var seconds = skew.TotalSeconds;
            if (Math.Abs(seconds) < 60)
            {
                _activeSign = 0;
                return false;
            }
            var sign = Math.Sign(seconds);
            if (sign == _activeSign) return false;
            _activeSign = sign;
            return true;
        }
    }
}
}
