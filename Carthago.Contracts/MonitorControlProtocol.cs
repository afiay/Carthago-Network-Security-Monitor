// SPDX-License-Identifier: MIT
namespace Carthago.Contracts;

public enum MonitorControlKind { Status = 1, Stop = 2 }
public enum MonitorControlState { Starting = 1, Monitoring = 2, Stopping = 3 }
public enum MonitorControlOutcome { Available = 1, StopAccepted = 2, StopDisabled = 3, SessionMismatch = 4, AlreadyStopping = 5 }
public sealed record MonitorControlRequest(int Version, Guid Correlation, MonitorControlKind Kind, Guid? SessionId = null);
public sealed record MonitorControlResponse(int Version, Guid Correlation, MonitorControlKind Kind,
    Guid SessionId, MonitorControlState State, MonitorControlOutcome Outcome, bool StopAllowed,
    DateTimeOffset ObservedUtc, DateTimeOffset? SampledUtc, ForegroundMonitorCounters? Counters);

public static class MonitorControlProtocol
{
    public const int Version = 4;
    public static void ValidateRequest(MonitorControlRequest q)
    {
        if (q.Version != Version || q.Correlation == Guid.Empty ||
            q.Kind is not (MonitorControlKind.Status or MonitorControlKind.Stop) ||
            (q.Kind == MonitorControlKind.Status && q.SessionId is not null) ||
            (q.Kind == MonitorControlKind.Stop && (q.SessionId is null || q.SessionId == Guid.Empty)))
            throw new InvalidDataException("Invalid monitor request.");
    }

    public static void ValidateResponse(MonitorControlResponse r, MonitorControlRequest q)
    {
        ValidateRequest(q);
        if (r.Version != Version || r.Correlation != q.Correlation || r.Kind != q.Kind ||
            r.SessionId == Guid.Empty || !Enum.IsDefined(r.State) || !Enum.IsDefined(r.Outcome) ||
            r.ObservedUtc == default || r.ObservedUtc.Offset != TimeSpan.Zero ||
            (r.SampledUtc is null) != (r.Counters is null) ||
            (r.SampledUtc is { } sampled && (sampled.Offset != TimeSpan.Zero || sampled == default || sampled > r.ObservedUtc)) ||
            (r.Counters is { } c && (c.Captured < 0 || c.Parsed < 0 || c.ParseErrors < 0 || c.Detections < 0)) ||
            (r.State == MonitorControlState.Starting && r.Counters is not null) ||
            (q.Kind == MonitorControlKind.Status && r.Outcome != MonitorControlOutcome.Available) ||
            (q.Kind == MonitorControlKind.Stop && r.Outcome == MonitorControlOutcome.Available) ||
            (r.Outcome == MonitorControlOutcome.SessionMismatch && q.SessionId == r.SessionId) ||
            (q.Kind == MonitorControlKind.Stop && r.Outcome != MonitorControlOutcome.SessionMismatch && q.SessionId != r.SessionId) ||
            (r.Outcome == MonitorControlOutcome.StopAccepted && (!r.StopAllowed || r.State == MonitorControlState.Stopping)) ||
            (r.Outcome == MonitorControlOutcome.StopDisabled && r.StopAllowed) ||
            (r.Outcome == MonitorControlOutcome.AlreadyStopping && r.State != MonitorControlState.Stopping))
            throw new InvalidDataException("Invalid monitor response.");
    }
}

/// <summary>Session-scoped stop authorization; no process killing or arbitrary command execution.</summary>
public sealed class MonitorControlSession
{
    private readonly object _gate = new();
    private readonly bool _allowStop;
    private readonly Action _cancel;
    private MonitorControlState _state = MonitorControlState.Starting;
    private ForegroundMonitorCounters? _counters;
    private DateTimeOffset? _sampledUtc;
    public Guid SessionId { get; } = Guid.NewGuid();

    public MonitorControlSession(bool allowStop, Action cancel)
    {
        _allowStop = allowStop;
        _cancel = cancel ?? throw new ArgumentNullException(nameof(cancel));
    }

    public void MarkStarted()
    {
        lock (_gate)
            if (_state == MonitorControlState.Starting) _state = MonitorControlState.Monitoring;
    }

    public void Publish(ForegroundMonitorCounters counters)
    {
        lock (_gate)
        {
            if (_state != MonitorControlState.Monitoring) return;
            _counters = counters;
            _sampledUtc = DateTimeOffset.UtcNow;
        }
    }

    public void MarkStopping()
    {
        lock (_gate) _state = MonitorControlState.Stopping;
    }

    public MonitorControlResponse Query(MonitorControlRequest q)
    {
        MonitorControlProtocol.ValidateRequest(q);
        lock (_gate)
        {
            var outcome = q.Kind == MonitorControlKind.Status ? MonitorControlOutcome.Available :
                q.SessionId != SessionId ? MonitorControlOutcome.SessionMismatch :
                !_allowStop ? MonitorControlOutcome.StopDisabled :
                _state == MonitorControlState.Stopping ? MonitorControlOutcome.AlreadyStopping :
                MonitorControlOutcome.StopAccepted;
            // Wall clock adjustments must not make a previously sampled counter frame invalid.
            var now = DateTimeOffset.UtcNow;
            if (_sampledUtc is { } sampled && sampled > now) now = sampled;
            return new(MonitorControlProtocol.Version, q.Correlation, q.Kind, SessionId,
                _state, outcome, _allowStop, now, _sampledUtc, _counters);
        }
    }

    // Called only after the client acknowledges the validated acceptance response.
    public void CommitStop(MonitorControlRequest request, MonitorControlResponse response)
    {
        MonitorControlProtocol.ValidateResponse(response, request);
        if (response.Outcome != MonitorControlOutcome.StopAccepted) return;
        lock (_gate)
        {
            if (!_allowStop || request.SessionId != SessionId || _state == MonitorControlState.Stopping) return;
            _state = MonitorControlState.Stopping;
        }
        _cancel();
    }
}
