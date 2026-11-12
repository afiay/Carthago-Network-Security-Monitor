// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Services;

internal static class EnrichmentEvaluationGuard
{
    // Enrichment failure must not suppress local detection. Session cancellation
    // is different: never evaluate a record after its run token is cancelled.
    internal static async Task RunAsync(Func<Task> enrich, Action evaluate,
        Action<Exception> reportFailure, CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested) return;

        try
        {
            await enrich().ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex)
        {
            // Provider timeout without run cancellation is also a failure.
            reportFailure(ex);
        }
        finally
        {
            if (!cancellationToken.IsCancellationRequested)
                evaluate();
        }
    }
}
