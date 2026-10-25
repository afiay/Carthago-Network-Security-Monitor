// SPDX-License-Identifier: MIT

using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Capture;

namespace Carthago.Services.Monitoring;

public sealed class CaptureSessionCoordinator : IAsyncDisposable
{
    private readonly MonitorLifecycle _lifecycle;
    private readonly Func<DateTime> _utcNow;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private ICaptureSource? _source;
    private Action<Exception>? _faultHandler;

    public CaptureSessionCoordinator(MonitorLifecycle lifecycle, Func<DateTime>? utcNow = null)
    {
        _lifecycle = lifecycle ?? throw new ArgumentNullException(nameof(lifecycle));
        _utcNow = utcNow ?? (() => DateTime.UtcNow);
    }

    public async Task StartAsync(
        ICaptureSource source,
        string sourceId,
        string sourceName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _lifecycle.BeginStart(sourceId, sourceName, _utcNow());
            _source = source;
            _faultHandler = exception => OnCaptureFaulted(source, exception);
            source.CaptureFaulted += _faultHandler;
            await source.StartAsync().WaitAsync(cancellationToken).ConfigureAwait(false);

            if (!source.IsRunning)
                throw new InvalidOperationException($"Capture source '{sourceName}' did not confirm startup.");

            _lifecycle.MarkStarted(_utcNow());
        }
        catch (Exception exception)
        {
            if (_lifecycle.Current.State is not (MonitorState.Failed or MonitorState.PermissionRequired))
                _lifecycle.MarkFailed(exception, _utcNow());
            await ReleaseSourceAsync(source).ConfigureAwait(false);
            if (ReferenceEquals(_source, source))
                _source = null;
            throw;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _lifecycle.BeginStop(_utcNow());

            if (_source is not null)
            {
                await ReleaseSourceAsync(_source).ConfigureAwait(false);
                _source = null;
            }

            _lifecycle.MarkStopped(_utcNow());
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_source is null)
                return;

            await ReleaseSourceAsync(_source).ConfigureAwait(false);
            _source = null;
        }
        finally
        {
            _gate.Release();
            _gate.Dispose();
        }
    }

    private async Task ReleaseSourceAsync(ICaptureSource source)
    {
        if (_faultHandler is not null)
        {
            source.CaptureFaulted -= _faultHandler;
            _faultHandler = null;
        }

        try
        {
            await source.StopAsync().ConfigureAwait(false);
        }
        catch
        {
            // Startup failures remain the primary error; disposal must still run.
        }
        finally
        {
            source.Dispose();
        }
    }

    private void OnCaptureFaulted(ICaptureSource source, Exception exception)
    {
        if (!ReferenceEquals(Volatile.Read(ref _source), source))
            return;

        var state = _lifecycle.Current.State;
        if (state is MonitorState.Stopping or MonitorState.Stopped or
            MonitorState.Failed or MonitorState.PermissionRequired)
        {
            return;
        }

        _lifecycle.MarkFailed(exception, _utcNow());
    }
}
