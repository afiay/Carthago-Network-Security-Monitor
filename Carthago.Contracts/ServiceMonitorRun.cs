// SPDX-License-Identifier: MIT
namespace Carthago.Contracts;

/// <summary>SCM-independent worker boundary. Startup is signaled only after the capture adapter starts.</summary>
public sealed class ServiceMonitorRun : IDisposable
{
    private readonly CancellationTokenSource _stop = new();
    private readonly TaskCompletionSource<bool> _started = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public Task Started => _started.Task;
    public Task<int> Completion { get; }

    public ServiceMonitorRun(ForegroundMonitorOptions options,
        Func<CancellationToken, Task<IForegroundCapture>> factory, TextWriter error,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        ArgumentNullException.ThrowIfNull(factory);
        if (options.EnableCliIpc || options.AllowCliStop) throw new ArgumentException("Service IPC disabled.");
        Completion = Task.Run(async () =>
        {
            try
            {
                _stop.Token.ThrowIfCancellationRequested();
                var capture = await factory(_stop.Token).ConfigureAwait(false);
                return await ForegroundMonitor.RunAsync(new StartupCapture(capture, _started), options,
                    TextWriter.Null, error, _stop.Token, delay).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { return 130; }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                await error.WriteLineAsync("Service capture initialization failed.");
                return 3;
            }
            finally
            {
                _started.TrySetException(new InvalidOperationException("Capture startup not confirmed."));
            }
        });
    }

    public void RequestStop() => _stop.Cancel();

    public void Dispose()
    {
        if (!Completion.IsCompleted) throw new InvalidOperationException("Worker still active.");
        _stop.Dispose();
    }

    private sealed class StartupCapture(IForegroundCapture inner, TaskCompletionSource<bool> started) : IForegroundCapture
    {
        public void Start(string interfaceId, string? filter)
        {
            inner.Start(interfaceId, filter);
            if (!inner.CaptureRequested) throw new InvalidOperationException("Capture did not confirm startup.");
            started.TrySetResult(true);
        }
        public bool CaptureRequested => inner.CaptureRequested;
        public ForegroundMonitorCounters ReadCounters() => inner.ReadCounters();
        public ValueTask DisposeAsync() => inner.DisposeAsync();
    }
}
