// SPDX-License-Identifier: MIT

using System;

namespace Carthago.Services.Monitoring;

public enum MonitorState
{
    Stopped,
    Starting,
    Running,
    RunningNoTraffic,
    Stopping,
    PermissionRequired,
    Failed
}

public sealed record MonitorStatusSnapshot
{
    public MonitorState State { get; init; } = MonitorState.Stopped;
    public Guid SessionId { get; init; }
    public string? SourceId { get; init; }
    public string? SourceName { get; init; }
    public DateTime StateChangedUtc { get; init; }
    public DateTime? StartRequestedUtc { get; init; }
    public DateTime? StartedUtc { get; init; }
    public DateTime? LastObservedPacketUtc { get; init; }
    public long PacketsReceived { get; init; }
    public long PacketsDecoded { get; init; }
    public long EventsPublished { get; init; }
    public long EventsDisplayed { get; init; }
    public long EventsExcludedByFilters { get; init; }
    public long ErrorsEncountered { get; init; }
    public string? LastError { get; init; }
}

public sealed class MonitorLifecycle
{
    private readonly object _gate = new();
    private readonly TimeSpan _noTrafficThreshold;
    private MonitorStatusSnapshot _current = new()
    {
        State = MonitorState.Stopped,
        StateChangedUtc = DateTime.UtcNow
    };

    public MonitorLifecycle(TimeSpan noTrafficThreshold)
    {
        if (noTrafficThreshold <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(noTrafficThreshold));

        _noTrafficThreshold = noTrafficThreshold;
    }

    public MonitorStatusSnapshot Current
    {
        get
        {
            lock (_gate)
                return _current;
        }
    }

    public MonitorStatusSnapshot BeginStart(string sourceId, string sourceName, DateTime nowUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceId);
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceName);

        lock (_gate)
        {
            _current = new MonitorStatusSnapshot
            {
                State = MonitorState.Starting,
                SessionId = Guid.NewGuid(),
                SourceId = sourceId,
                SourceName = sourceName,
                StateChangedUtc = NormalizeUtc(nowUtc),
                StartRequestedUtc = NormalizeUtc(nowUtc)
            };
            return _current;
        }
    }

    public MonitorStatusSnapshot MarkStarted(DateTime nowUtc)
    {
        lock (_gate)
        {
            if (_current.State != MonitorState.Starting)
                throw new InvalidOperationException($"Cannot mark monitoring started from {_current.State}.");

            var utc = NormalizeUtc(nowUtc);
            _current = _current with
            {
                State = MonitorState.Running,
                StateChangedUtc = utc,
                StartedUtc = utc,
                LastError = null
            };
            return _current;
        }
    }

    public MonitorStatusSnapshot EvaluateTrafficState(DateTime nowUtc)
    {
        lock (_gate)
        {
            if (_current.State is not (MonitorState.Running or MonitorState.RunningNoTraffic) ||
                !_current.StartedUtc.HasValue)
            {
                return _current;
            }

            var utc = NormalizeUtc(nowUtc);
            var lastActivity = _current.LastObservedPacketUtc ?? _current.StartedUtc.Value;
            var nextState = utc - lastActivity >= _noTrafficThreshold
                ? MonitorState.RunningNoTraffic
                : MonitorState.Running;

            if (nextState == _current.State)
                return _current;

            _current = _current with
            {
                State = nextState,
                StateChangedUtc = utc
            };
            return _current;
        }
    }

    public MonitorStatusSnapshot RecordPacketObserved(DateTime nowUtc)
    {
        lock (_gate)
        {
            if (_current.State is not (MonitorState.Running or MonitorState.RunningNoTraffic))
                return _current;

            var utc = NormalizeUtc(nowUtc);
            var stateChanged = _current.State != MonitorState.Running;
            _current = _current with
            {
                State = MonitorState.Running,
                StateChangedUtc = stateChanged ? utc : _current.StateChangedUtc,
                LastObservedPacketUtc = utc,
                PacketsReceived = _current.PacketsReceived + 1
            };
            return _current;
        }
    }

    public MonitorStatusSnapshot MarkFailed(Exception exception, DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(exception);

        lock (_gate)
        {
            var utc = NormalizeUtc(nowUtc);
            _current = _current with
            {
                State = exception is UnauthorizedAccessException
                    ? MonitorState.PermissionRequired
                    : MonitorState.Failed,
                StateChangedUtc = utc,
                ErrorsEncountered = _current.ErrorsEncountered + 1,
                LastError = exception.Message
            };
            return _current;
        }
    }

    public MonitorStatusSnapshot RecordPacketDecoded()
    {
        lock (_gate)
        {
            _current = _current with { PacketsDecoded = _current.PacketsDecoded + 1 };
            return _current;
        }
    }

    public MonitorStatusSnapshot RecordEventPublished()
    {
        lock (_gate)
        {
            _current = _current with { EventsPublished = _current.EventsPublished + 1 };
            return _current;
        }
    }

    public MonitorStatusSnapshot RecordEventDisplayed(int count = 1)
    {
        if (count <= 0)
            throw new ArgumentOutOfRangeException(nameof(count));

        lock (_gate)
        {
            _current = _current with { EventsDisplayed = _current.EventsDisplayed + count };
            return _current;
        }
    }

    public MonitorStatusSnapshot RecordEventExcludedByFilter(int count = 1)
    {
        if (count <= 0)
            throw new ArgumentOutOfRangeException(nameof(count));

        lock (_gate)
        {
            _current = _current with { EventsExcludedByFilters = _current.EventsExcludedByFilters + count };
            return _current;
        }
    }

    public MonitorStatusSnapshot BeginStop(DateTime nowUtc)
    {
        lock (_gate)
        {
            if (_current.State == MonitorState.Stopped)
                return _current;

            _current = _current with
            {
                State = MonitorState.Stopping,
                StateChangedUtc = NormalizeUtc(nowUtc)
            };
            return _current;
        }
    }

    public MonitorStatusSnapshot MarkStopped(DateTime nowUtc)
    {
        lock (_gate)
        {
            _current = _current with
            {
                State = MonitorState.Stopped,
                StateChangedUtc = NormalizeUtc(nowUtc)
            };
            return _current;
        }
    }

    private static DateTime NormalizeUtc(DateTime value) => value.Kind switch
    {
        DateTimeKind.Utc => value,
        DateTimeKind.Local => value.ToUniversalTime(),
        _ => DateTime.SpecifyKind(value, DateTimeKind.Utc)
    };
}
