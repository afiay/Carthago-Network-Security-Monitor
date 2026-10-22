// SPDX-License-Identifier: MIT
// File: Sinks/SinkManager.cs
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Sinks
{
    /// <summary>
    /// Optional interface a sink can implement to receive batches efficiently.
    /// If not implemented, the manager will fan-out single events to EmitAsync().
    /// </summary>
    public interface IBatchableSink : IDetectionSink
    {
        /// <summary>Emit a batch of events as a single call for higher throughput.</summary>
        Task EmitBatchAsync(IReadOnlyList<DetectionEvent> events, CancellationToken ct = default);
    }

    // ===== UI-facing event payloads =====
    public sealed class SinkEmitEventArgs : EventArgs
    {
        public string SinkName { get; }
        public int Count { get; }
        public DateTime TimestampUtc { get; }
        /// <summary>Compat alias for existing code that reads ".Utc".</summary>
        public DateTime Utc => TimestampUtc;
        /// <summary>First event for convenience (may be null if Count==0).</summary>
        public DetectionEvent? Event { get; }
        /// <summary>All events that were emitted in this operation (batch or single).</summary>
        public IReadOnlyList<DetectionEvent> Events { get; }
        public double? LatencyMs { get; }

        public SinkEmitEventArgs(string sinkName, IReadOnlyList<DetectionEvent> events, double? latencyMs)
        {
            SinkName = sinkName;
            Events = events ?? Array.Empty<DetectionEvent>();
            Count = Events.Count;
            Event = Count > 0 ? Events[0] : null;
            TimestampUtc = DateTime.UtcNow;
            LatencyMs = latencyMs;
        }
    }

    public sealed class SinkErrorEventArgs : EventArgs
    {
        public string SinkName { get; }
        public int Count { get; }
        public DateTime TimestampUtc { get; }
        /// <summary>Compat alias for existing code that reads ".Utc".</summary>
        public DateTime Utc => TimestampUtc;
        public DetectionEvent? Event { get; }
        public IReadOnlyList<DetectionEvent> Events { get; }
        public Exception Exception { get; }
        public string Message { get; }

        public SinkErrorEventArgs(string sinkName, IReadOnlyList<DetectionEvent> events, Exception ex, string message)
        {
            SinkName = sinkName;
            Events = events ?? Array.Empty<DetectionEvent>();
            Count = Events.Count;
            Event = Count > 0 ? Events[0] : null;
            TimestampUtc = DateTime.UtcNow;
            Exception = ex;
            Message = message;
        }
    }

    /// <summary>
    /// Configuration knobs for SinkManager.
    /// Defaults are conservative, focused on stability.
    /// </summary>
    public sealed class SinkManagerOptions
    {
        public int PerSinkQueueCapacity { get; init; } = 4096;
        public int MaxBatchSize { get; init; } = 128;
        public TimeSpan MaxBatchWindow { get; init; } = TimeSpan.FromMilliseconds(150);
        public TimeSpan PerAttemptTimeout { get; init; } = TimeSpan.FromSeconds(8);
        public int MaxRetries { get; init; } = 3;
        public TimeSpan InitialBackoff { get; init; } = TimeSpan.FromMilliseconds(250);
        public int BreakerTripFailures { get; init; } = 8;
        public TimeSpan BreakerOpenFor { get; init; } = TimeSpan.FromSeconds(20);
        public int BreakerHalfOpenProbes { get; init; } = 1;
        public bool DropCurrentOnOverflow { get; init; } = false;
        public bool VerboseConsoleLogs { get; init; } = false;
    }

    /// <summary>
    /// Per-sink metrics snapshot for UI/diagnostics.
    /// </summary>
    public sealed class SinkMetrics
    {
        public string SinkName { get; set; } = ""; // changed from init to set
        public long Enqueued => _enqueued;
        public long Dropped => _dropped;
        public long Succeeded => _succeeded;
        public long Failed => _failed;
        public int QueueLength => _queueLength;
        public int ConsecutiveFailures => _consecFailures;
        public bool CircuitOpen => _circuitOpen == 1;
        public DateTime? LastSuccessUtc => _lastSuccessUtc;
        public DateTime? LastFailureUtc => _lastFailureUtc;
        public double? LastLatencyMs => _lastLatencyMs;

        internal long _enqueued, _dropped, _succeeded, _failed;
        internal int _queueLength, _consecFailures;
        internal int _circuitOpen; // 0/1
        internal DateTime? _lastSuccessUtc, _lastFailureUtc;
        internal double? _lastLatencyMs;
    }

    /// <summary>
    /// SinkManager with bounded queues, batching, retries, timeouts, and circuit breaker per sink.
    /// Also raises UI-friendly events on success/failure.
    /// </summary>
    public sealed class SinkManager : IDisposable
    {
        private readonly List<SinkWorker> _workers = new();
        private readonly CancellationTokenSource _cts = new();
        private readonly SinkManagerOptions _opt;

        // UI-layer events
        public event EventHandler<SinkEmitEventArgs>? SinkEmitted;
        public event EventHandler<SinkErrorEventArgs>? SinkFailed;

        internal void RaiseEmitted(SinkEmitEventArgs e) => SinkEmitted?.Invoke(this, e);
        internal void RaiseFailed(SinkErrorEventArgs e)
        {
            foreach (var evt in e.Events ?? Array.Empty<DetectionEvent>())
            {
                evt.ExternalDeliveryStatus = ExternalSinkDeliveryStatus.Failed;
                evt.LastSinkName = e.SinkName;
                evt.LastSinkError = e.Message;
                evt.LastSinkAttemptUtc = e.TimestampUtc;
                evt.SinkFailureCount++;

                try
                {
                    DetectionOutbox.Current
                        .AppendPendingAsync(evt, e.SinkName, e.Message)
                        .GetAwaiter()
                        .GetResult();
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[SinkManager] outbox spool failed for {evt.EventId}: {ex.Message}");
                }
            }

            Console.Error.WriteLine($"[SinkManager] {e.SinkName} failed: {e.Message}");
            SinkFailed?.Invoke(this, e);
        }

        public SinkManager(IDetectionSink[] sinks, SinkManagerOptions? options = null)
        {
            _opt = options ?? new SinkManagerOptions();
            foreach (var s in sinks ?? Array.Empty<IDetectionSink>())
            {
                _workers.Add(new SinkWorker(this, s, _opt, _cts.Token));
            }
        }

        public SinkManager(params IDetectionSink[] sinks) : this(sinks, null) { }

        /// <summary>
        /// Enqueue to all sinks. Fast-path: returns immediately.
        /// Confirmed DetectionEvents are backpressured instead of silently dropped.
        /// </summary>
        public async ValueTask EnqueueAsync(DetectionEvent evt, CancellationToken ct = default)
        {
            if (evt == null || ct.IsCancellationRequested) return;
            foreach (var w in _workers)
                await w.EnqueueAsync(evt, ct).ConfigureAwait(false);
        }

        public Task EmitAllAsync(DetectionEvent evt, CancellationToken ct = default)
            => EnqueueAsync(evt, ct).AsTask();

        /// <summary>Per-sink metrics snapshot for a WPF page or diagnostics endpoint.</summary>
        public IReadOnlyList<SinkMetrics> GetMetrics()
        {
            var arr = new List<SinkMetrics>(_workers.Count);
            foreach (var w in _workers) arr.Add(w.Snapshot());
            return arr;
        }

        public void Dispose()
        {
            try
            {
                _cts.Cancel();
                Task.WhenAll(_workers.Select(w => w.StopAsync()).ToArray()).Wait(TimeSpan.FromSeconds(5));
            }
            catch { /* best-effort */ }
            finally
            {
                foreach (var w in _workers) w.Dispose();
                _cts.Dispose();
            }
        }

        // ====================== inner types ======================

        private sealed class SinkWorker : IDisposable
        {
            private readonly record struct SendResult(bool Succeeded, Exception? Error);

            private readonly SinkManager _owner;
            private readonly IDetectionSink _sink;
            private readonly IBatchableSink? _batchSink;
            private readonly SinkManagerOptions _opt;
            private readonly Channel<DetectionEvent> _channel;
            private readonly CancellationToken _rootCt;
            private readonly Task _pump;
            private readonly SinkMetrics _m = new();

            // breaker state
            private DateTime _breakerOpenedUtc = DateTime.MinValue;
            private int _halfOpenInFlight;

            public SinkWorker(SinkManager owner, IDetectionSink sink, SinkManagerOptions opt, CancellationToken rootCt)
            {
                _owner = owner ?? throw new ArgumentNullException(nameof(owner));
                _sink = sink ?? throw new ArgumentNullException(nameof(sink));
                _batchSink = sink as IBatchableSink;
                _opt = opt ?? throw new ArgumentNullException(nameof(opt));
                _rootCt = rootCt;

                _m.SinkName = sink.GetType().Name;

                var cap = Math.Max(16, _opt.PerSinkQueueCapacity);
                var options = new BoundedChannelOptions(cap)
                {
                    SingleReader = true,
                    SingleWriter = false,
                    FullMode = BoundedChannelFullMode.Wait
                };
                _channel = Channel.CreateBounded<DetectionEvent>(options);

                _pump = Task.Run(() => PumpAsync());
            }

            public SinkMetrics Snapshot()
            {
                // copy volatile counters to a snapshot instance
                return new SinkMetrics
                {
                    SinkName = _m.SinkName,
                    _enqueued = _m._enqueued,
                    _dropped = _m._dropped,
                    _succeeded = _m._succeeded,
                    _failed = _m._failed,
                    _queueLength = _m._queueLength,
                    _consecFailures = _m._consecFailures,
                    _circuitOpen = _m._circuitOpen,
                    _lastSuccessUtc = _m._lastSuccessUtc,
                    _lastFailureUtc = _m._lastFailureUtc,
                    _lastLatencyMs = _m._lastLatencyMs,
                };
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public async ValueTask EnqueueAsync(DetectionEvent evt, CancellationToken ct = default)
            {
                try
                {
                    evt.ExternalDeliveryStatus = ExternalSinkDeliveryStatus.Pending;
                    evt.LastSinkName = _m.SinkName;
                    evt.LastSinkAttemptUtc = DateTime.UtcNow;
                    await _channel.Writer.WriteAsync(evt, ct).ConfigureAwait(false);
                    Interlocked.Increment(ref _m._enqueued);
                    Interlocked.Exchange(ref _m._queueLength, Math.Min(_opt.PerSinkQueueCapacity, _m._queueLength + 1));
                }
                catch (OperationCanceledException ex)
                {
                    evt.ExternalDeliveryStatus = ExternalSinkDeliveryStatus.Failed;
                    RuleEngineHealthState.ReportSinkQueueBackpressure(ex.Message);
                    RuleEngineMetrics.Increment(evt.RuleId, RuleMetricNames.RuleSinkFailedTotal);
                    _owner.RaiseFailed(new SinkErrorEventArgs(_m.SinkName, new[] { evt }, ex, ex.Message));
                }
                catch (Exception ex)
                {
                    evt.ExternalDeliveryStatus = ExternalSinkDeliveryStatus.Failed;
                    RuleEngineHealthState.ReportSinkQueueBackpressure(ex.Message);
                    RuleEngineMetrics.Increment(evt.RuleId, RuleMetricNames.RuleSinkFailedTotal);
                    _owner.RaiseFailed(new SinkErrorEventArgs(_m.SinkName, new[] { evt }, ex, ex.Message));
                }
            }

            public async Task StopAsync()
            {
                _channel.Writer.TryComplete();
                try { await _pump.ConfigureAwait(false); } catch { /* ignore */ }
            }

            private async Task PumpAsync()
            {
                // Single reader, batch if possible
                var reader = _channel.Reader;
                var batch = new List<DetectionEvent>(_opt.MaxBatchSize);

                while (!_rootCt.IsCancellationRequested)
                {
                    try
                    {
                        // Wait for at least one item
                        if (!await reader.WaitToReadAsync(_rootCt).ConfigureAwait(false))
                            break;

                        batch.Clear();
                        // Read first item
                        if (reader.TryRead(out var first)) batch.Add(first);

                        // Try to fill up to MaxBatchSize within MaxBatchWindow
                        var sw = Stopwatch.StartNew();
                        while (batch.Count < _opt.MaxBatchSize && sw.Elapsed < _opt.MaxBatchWindow && reader.TryRead(out var next))
                            batch.Add(next);

                        // Breaker gate
                        if (IsCircuitOpen())
                        {
                            RuleEngineHealthState.ReportSinkQueueBackpressure("sink circuit open");
                            foreach (var e in batch) { e.ExternalDeliveryStatus = ExternalSinkDeliveryStatus.Failed; RuleEngineMetrics.Increment(e.RuleId, RuleMetricNames.RuleSinkFailedTotal); }
                            Interlocked.Add(ref _m._failed, batch.Count);
                            _owner.RaiseFailed(new SinkErrorEventArgs(_m.SinkName, batch.ToArray(), new InvalidOperationException("Sink circuit open"), "Sink circuit open; events remain in local journal."));
                            Interlocked.Exchange(ref _m._queueLength, Math.Max(0, _m._queueLength - batch.Count));
                            continue;
                        }

                        // Half-open gating
                        if (IsHalfOpen() && Interlocked.Increment(ref _halfOpenInFlight) > _opt.BreakerHalfOpenProbes)
                        {
                            Interlocked.Decrement(ref _halfOpenInFlight);
                            RuleEngineHealthState.ReportSinkQueueBackpressure("half-open probe limit");
                            foreach (var e in batch) { e.ExternalDeliveryStatus = ExternalSinkDeliveryStatus.Failed; RuleEngineMetrics.Increment(e.RuleId, RuleMetricNames.RuleSinkFailedTotal); }
                            Interlocked.Add(ref _m._failed, batch.Count);
                            Interlocked.Exchange(ref _m._queueLength, Math.Max(0, _m._queueLength - batch.Count));
                            continue;
                        }

                        using var attemptCt = MakeTimeoutToken(_opt.PerAttemptTimeout, _rootCt);
                        var t0 = Stopwatch.GetTimestamp();
                        var sendResult = await SendWithRetryAsync(batch, attemptCt.Token).ConfigureAwait(false);
                        var latencyMs = ElapsedMs(t0);
                        _m._lastLatencyMs = latencyMs;

                        if (_rootCt.IsCancellationRequested)
                            break;

                        if (sendResult.Succeeded)
                        {
                            Interlocked.Add(ref _m._succeeded, batch.Count);
                            Interlocked.Exchange(ref _m._consecFailures, 0);
                            _m._lastSuccessUtc = DateTime.UtcNow;

                            if (IsHalfOpen()) CloseBreaker();

                            // raise success event
                            foreach (var e in batch)
                            {
                                e.ExternalDeliveryStatus = ExternalSinkDeliveryStatus.Delivered;
                                e.LastSinkName = _m.SinkName;
                                e.LastSinkError = null;
                                e.LastSinkAttemptUtc = DateTime.UtcNow;
                                e.SinkSuccessCount++;
                            }
                            _owner.RaiseEmitted(new SinkEmitEventArgs(_m.SinkName, batch.ToArray(), latencyMs));
                        }
                        else
                        {
                            Interlocked.Add(ref _m._failed, batch.Count);
                            var fails = Interlocked.Increment(ref _m._consecFailures);
                            _m._lastFailureUtc = DateTime.UtcNow;
                            var error = sendResult.Error ?? new Exception("Emit failed after retries");
                            foreach (var e in batch) { e.ExternalDeliveryStatus = ExternalSinkDeliveryStatus.Failed; RuleEngineMetrics.Increment(e.RuleId, RuleMetricNames.RuleSinkFailedTotal); }

                            // raise failure event
                            _owner.RaiseFailed(new SinkErrorEventArgs(_m.SinkName, batch.ToArray(),
                                error, error.Message));

                            if (fails >= _opt.BreakerTripFailures)
                                OpenBreaker();
                        }

                        if (IsHalfOpen())
                            Interlocked.Exchange(ref _halfOpenInFlight, 0);

                        // queue length bookkeeping
                        Interlocked.Exchange(ref _m._queueLength,
                            Math.Max(0, _m._queueLength - batch.Count));
                    }
                    catch (OperationCanceledException) { break; }
                    catch (Exception ex)
                    {
                        if (_opt.VerboseConsoleLogs)
                            Console.Error.WriteLine($"[SinkPump] {_m.SinkName}: {ex.Message}");

                        // also surface as a failure event with whatever we had in 'batch'
                        if (batch.Count > 0)
                        {
                            _owner.RaiseFailed(new SinkErrorEventArgs(_m.SinkName, batch.ToArray(), ex, ex.Message));
                            Interlocked.Add(ref _m._failed, batch.Count);
                            Interlocked.Exchange(ref _m._queueLength,
                                Math.Max(0, _m._queueLength - batch.Count));
                        }
                    }
                }
            }

            private async Task<SendResult> SendWithRetryAsync(List<DetectionEvent> batch, CancellationToken ct)
            {
                int attempt = 0;
                var backoff = _opt.InitialBackoff;
                Exception? lastError = null;

                while (true)
                {
                    try
                    {
                        if (_batchSink != null && batch.Count > 1)
                        {
                            await _batchSink.EmitBatchAsync(batch, ct).ConfigureAwait(false);
                        }
                        else
                        {
                            foreach (var e in batch)
                                await _sink.EmitAsync(e, ct).ConfigureAwait(false);
                        }
                        return new SendResult(true, null);
                    }
                    catch (OperationCanceledException ex)
                    {
                        return new SendResult(false, ex);
                    }
                    catch (Exception ex)
                    {
                        lastError = ex;
                        attempt++;
                        if (_opt.VerboseConsoleLogs)
                            Console.Error.WriteLine($"[SinkSend] {_m.SinkName}: attempt {attempt} failed: {Mask(ex.Message)}");

                        if (attempt > _opt.MaxRetries)
                            return new SendResult(false, lastError);

                        try { await Task.Delay(backoff, ct).ConfigureAwait(false); }
                        catch (OperationCanceledException delayEx) { return new SendResult(false, delayEx); }

                        backoff = TimeSpan.FromMilliseconds(Math.Min(backoff.TotalMilliseconds * 2, 8000));
                    }
                }
            }

            private bool IsCircuitOpen()
            {
                if (Volatile.Read(ref _m._circuitOpen) == 1)
                {
                    if (DateTime.UtcNow - _breakerOpenedUtc >= _opt.BreakerOpenFor)
                        return false; // half-open
                    return true;
                }
                return false;
            }

            private bool IsHalfOpen()
            {
                if (Volatile.Read(ref _m._circuitOpen) == 1)
                {
                    if (DateTime.UtcNow - _breakerOpenedUtc >= _opt.BreakerOpenFor)
                        return true;
                }
                return false;
            }

            private void OpenBreaker()
            {
                _breakerOpenedUtc = DateTime.UtcNow;
                Interlocked.Exchange(ref _m._circuitOpen, 1);
                if (_opt.VerboseConsoleLogs)
                    Console.Error.WriteLine($"[SinkBreaker] {_m.SinkName}: OPEN (failures={_m._consecFailures}).");
            }

            private void CloseBreaker()
            {
                Interlocked.Exchange(ref _m._circuitOpen, 0);
                Interlocked.Exchange(ref _m._consecFailures, 0);
                if (_opt.VerboseConsoleLogs)
                    Console.WriteLine($"[SinkBreaker] {_m.SinkName}: CLOSED.");
            }

            private static double ElapsedMs(long startTs)
            {
                var ticks = Stopwatch.GetTimestamp() - startTs;
                return ticks * 1000.0 / Stopwatch.Frequency;
            }

            private static string Mask(string? s)
            {
                if (string.IsNullOrEmpty(s)) return "";
                return s.Length <= 8 ? "********" : s.Substring(0, Math.Min(4, s.Length)) + "****";
            }

            private static CancellationTokenSource MakeTimeoutToken(TimeSpan timeout, CancellationToken parent)
            {
                var cts = CancellationTokenSource.CreateLinkedTokenSource(parent);
                cts.CancelAfter(timeout);
                return cts;
            }

            public void Dispose()
            {
                try { _sink.Dispose(); } catch { }
            }
        }
    }
}
