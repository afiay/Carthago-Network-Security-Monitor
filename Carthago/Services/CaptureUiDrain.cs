// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Carthago.Services
{
    /// <summary>Drains a bounded capture queue without concealing unexpected reader failures.</summary>
    public static class CaptureUiDrain
    {
        public static async Task RunAsync<T>(
            ChannelReader<T> reader, int batchSize,
            Func<IReadOnlyList<T>, Task> deliverAsync, CancellationToken cancellationToken)
        {
            if (reader == null) throw new ArgumentNullException(nameof(reader));
            if (deliverAsync == null) throw new ArgumentNullException(nameof(deliverAsync));
            if (batchSize <= 0) throw new ArgumentOutOfRangeException(nameof(batchSize));

            try
            {
                await foreach (var first in reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
                {
                    var batch = new List<T>(batchSize) { first };
                    while (batch.Count < batchSize && reader.TryRead(out var next))
                        batch.Add(next);
                    await deliverAsync(batch).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // Expected when the service is disposed.
            }
            catch (ChannelClosedException ex) when (ex.InnerException != null)
            {
                ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
                throw;
            }
        }
    }
}
