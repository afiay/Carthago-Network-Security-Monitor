using System;

namespace Carthago.Services
{
    [Flags]
    public enum DashboardAnalyticsRefreshKind
    {
        None = 0,
        Incidents = 1,
        Anomalies = 2,
        Baseline = 4,
        All = Incidents | Anomalies | Baseline
    }

    /// <summary>Combines related dashboard refresh signals into bounded dispatcher work.</summary>
    public sealed class DashboardAnalyticsRefreshCoalescer
    {
        internal static readonly TimeSpan DefaultMinimumInterval = TimeSpan.FromSeconds(2);

        private readonly object _sync = new();
        private readonly TimeSpan _minimumInterval;
        private readonly TimeProvider _timeProvider;
        private DashboardAnalyticsRefreshKind _pending;
        private long _cadenceAnchorTimestamp;
        private bool _scheduled;
        private bool _executing;
        private bool _canceled;

        public DashboardAnalyticsRefreshCoalescer()
            : this(DefaultMinimumInterval, TimeProvider.System)
        {
        }

        internal DashboardAnalyticsRefreshCoalescer(
            TimeSpan minimumInterval,
            TimeProvider timeProvider)
        {
            if (minimumInterval <= TimeSpan.Zero)
                throw new ArgumentOutOfRangeException(nameof(minimumInterval));

            _minimumInterval = minimumInterval;
            _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        }

        public bool Request(DashboardAnalyticsRefreshKind kind)
        {
            if (kind == DashboardAnalyticsRefreshKind.None ||
                (kind & ~DashboardAnalyticsRefreshKind.All) != 0)
                throw new ArgumentOutOfRangeException(nameof(kind));

            lock (_sync)
            {
                if (_canceled)
                    return false;

                _pending |= kind;
                if (_scheduled || _executing)
                    return false;

                _cadenceAnchorTimestamp = _timeProvider.GetTimestamp();
                _scheduled = true;
                return true;
            }
        }

        public TimeSpan GetDelayUntilNextRefresh()
        {
            lock (_sync)
            {
                return GetDelayUntilNextRefreshCore();
            }
        }

        public bool TryBeginRefresh(
            out DashboardAnalyticsRefreshKind pending,
            out TimeSpan retryAfter)
        {
            lock (_sync)
            {
                pending = DashboardAnalyticsRefreshKind.None;
                retryAfter = TimeSpan.Zero;

                if (_canceled || !_scheduled || _executing)
                    return false;

                retryAfter = GetDelayUntilNextRefreshCore();
                if (retryAfter > TimeSpan.Zero)
                    return false;

                _scheduled = false;
                _executing = true;
                pending = _pending;
                _pending = DashboardAnalyticsRefreshKind.None;
                return true;
            }
        }

        public bool CompleteRefresh()
        {
            lock (_sync)
            {
                if (!_executing)
                    return false;

                _executing = false;
                if (_canceled)
                {
                    _pending = DashboardAnalyticsRefreshKind.None;
                    return false;
                }

                _cadenceAnchorTimestamp = _timeProvider.GetTimestamp();
                if (_pending == DashboardAnalyticsRefreshKind.None)
                    return false;

                _scheduled = true;
                return true;
            }
        }

        public void Cancel()
        {
            lock (_sync)
            {
                _canceled = true;
                _scheduled = false;
                _pending = DashboardAnalyticsRefreshKind.None;
            }
        }

        private TimeSpan GetDelayUntilNextRefreshCore()
        {
            if (_canceled || !_scheduled)
                return TimeSpan.Zero;

            var elapsed = _timeProvider.GetElapsedTime(
                _cadenceAnchorTimestamp,
                _timeProvider.GetTimestamp());
            var remaining = _minimumInterval - elapsed;
            return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
        }
    }
}
