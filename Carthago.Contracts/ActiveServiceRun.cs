// SPDX-License-Identifier: MIT
namespace Carthago.Contracts;

// SCM-independent lifecycle; readiness is explicit and cannot be inferred
// from task creation or configuration parsing.
public sealed class ActiveServiceRun : IDisposable
{
    private readonly CancellationTokenSource _stop = new();
    private readonly TaskCompletionSource<bool> _started = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public Task Started => _started.Task;
    public Task<int> Completion { get; }

    public ActiveServiceRun(Func<CancellationToken, Action, Task<int>> execute)
    {
        ArgumentNullException.ThrowIfNull(execute);
        Completion = Task.Run(async () =>
        {
            try
            {
                _stop.Token.ThrowIfCancellationRequested();
                return await execute(_stop.Token, () =>
                {
                    _stop.Token.ThrowIfCancellationRequested();
                    _started.TrySetResult(true);
                }).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { return 130; }
            catch (Exception ex) when (ex is not OutOfMemoryException) { return 3; }
            finally { _started.TrySetException(new InvalidOperationException("Active scheduler startup not confirmed.")); }
        });
    }
    public void RequestStop() => _stop.Cancel();
    public void Dispose()
    {
        if (!Completion.IsCompleted) throw new InvalidOperationException("Active worker still running.");
        _stop.Dispose();
    }
}
