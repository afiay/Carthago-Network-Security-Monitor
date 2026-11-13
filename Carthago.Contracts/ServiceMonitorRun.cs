// SPDX-License-Identifier: MIT
namespace Carthago.Contracts;

/// <summary>SCM-independent worker boundary. Startup requires a confirmed capture and successful first health sample.</summary>
public sealed class ServiceMonitorRun : IDisposable
{
    private readonly CancellationTokenSource _stop = new();
    private readonly TaskCompletionSource<bool> _started = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public Task Started => _started.Task;
    public Task<int> Completion { get; }

    public ServiceMonitorRun(ForegroundMonitorOptions options,
        Func<CancellationToken, Task<IForegroundCapture>> factory, TextWriter error,
        Func<TimeSpan, CancellationToken, Task>? delay = null, Action<ForegroundMonitorCounters>? sample = null)
    {
        ArgumentNullException.ThrowIfNull(factory);
        if (options.EnableCliIpc || options.AllowCliStop) throw new ArgumentException("Service IPC disabled.");
        Completion = Task.Run(async () =>
        {
            try
            {
                _stop.Token.ThrowIfCancellationRequested();
                var capture = await factory(_stop.Token).ConfigureAwait(false);
                return await ForegroundMonitor.RunAsync(capture, options, TextWriter.Null, error,
                    _stop.Token, delay, sample: counters =>
                    {
                        // ForegroundMonitor has confirmed CaptureRequested and read counters.
                        // In SCM mode, sample persists the health snapshot. A failed first
                        // publication must not signal readiness to the service controller.
                        _stop.Token.ThrowIfCancellationRequested();
                        sample?.Invoke(counters);
                        _stop.Token.ThrowIfCancellationRequested();
                        _started.TrySetResult(true);
                    }).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { return 130; }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                await error.WriteLineAsync("Service capture initialization failed.");
                return 3;
            }
            finally
            {
                _started.TrySetException(new InvalidOperationException("Capture startup and first health sample not confirmed."));
            }
        });
    }

    public void RequestStop() => _stop.Cancel();

    public void Dispose()
    {
        if (!Completion.IsCompleted) throw new InvalidOperationException("Worker still active.");
        _stop.Dispose();
    }

}
