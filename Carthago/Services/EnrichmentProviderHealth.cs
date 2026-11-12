// SPDX-License-Identifier: MIT
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Services;

public sealed record EnrichmentProviderSnapshot(long Success, long Unavailable,
    long Failed, long TimedOut, long Cancelled, long CacheHits,
    long TotalElapsedMs, long MaxElapsedMs);

internal enum EnrichmentLookupStatus { Success, Unavailable, Failed, TimedOut, Cancelled }
internal sealed record EnrichmentLookup<T>(EnrichmentLookupStatus Status, T? Value) where T : class;

internal sealed class EnrichmentProviderHealth
{
    private sealed class Counters
    {
        internal long Success, Unavailable, Failed, TimedOut, Cancelled, CacheHits, TotalElapsedMs, MaxElapsedMs;
    }

    private readonly ConcurrentDictionary<string, Counters> _providers = new(StringComparer.Ordinal);
    private Counters Get(string provider) => _providers.GetOrAdd(provider, _ => new Counters());

    internal void RecordCacheHit(string provider) => Interlocked.Increment(ref Get(provider).CacheHits);

    internal async Task<EnrichmentLookup<T>> LookupAsync<T>(string provider,
        Func<CancellationToken, Task<T?>> fetch, TimeSpan budget, CancellationToken sessionToken) where T : class
    {
        var counters = Get(provider);
        long start = Stopwatch.GetTimestamp();
        var status = EnrichmentLookupStatus.Failed;
        Task<T?>? pending = null;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(sessionToken);
        deadline.CancelAfter(budget);
        try
        {
            deadline.Token.ThrowIfCancellationRequested();
            // Fetch only returns a value; never mutate a TrafficRecord inside this delegate.
            pending = fetch(deadline.Token);
            var value = await pending.WaitAsync(deadline.Token).ConfigureAwait(false);
            deadline.Token.ThrowIfCancellationRequested();
            status = value is null ? EnrichmentLookupStatus.Unavailable : EnrichmentLookupStatus.Success;
            return new(status, value);
        }
        catch (OperationCanceledException)
        {
            status = sessionToken.IsCancellationRequested ? EnrichmentLookupStatus.Cancelled
                : deadline.IsCancellationRequested ? EnrichmentLookupStatus.TimedOut : EnrichmentLookupStatus.Failed;
            return new(status, null);
        }
        catch (TimeoutException)
        {
            status = EnrichmentLookupStatus.TimedOut;
            return new(status, null);
        }
        catch (Exception)
        {
            status = EnrichmentLookupStatus.Failed;
            return new(status, null);
        }
        finally
        {
            // A non-cooperative provider may finish after the caller's deadline.
            // Observe any later fault; its result is never applied to the record.
            if (pending is not null && !pending.IsCompletedSuccessfully)
                _ = pending.ContinueWith(t => { _ = t.Exception; },
                    CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);

            switch (status)
            {
                case EnrichmentLookupStatus.Success: Interlocked.Increment(ref counters.Success); break;
                case EnrichmentLookupStatus.Unavailable: Interlocked.Increment(ref counters.Unavailable); break;
                case EnrichmentLookupStatus.TimedOut: Interlocked.Increment(ref counters.TimedOut); break;
                case EnrichmentLookupStatus.Cancelled: Interlocked.Increment(ref counters.Cancelled); break;
                default: Interlocked.Increment(ref counters.Failed); break;
            }
            long elapsed = (long)Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            Interlocked.Add(ref counters.TotalElapsedMs, elapsed);
            long observed;
            do { observed = Interlocked.Read(ref counters.MaxElapsedMs); }
            while (elapsed > observed && Interlocked.CompareExchange(ref counters.MaxElapsedMs, elapsed, observed) != observed);
        }
    }

    internal IReadOnlyDictionary<string, EnrichmentProviderSnapshot> Snapshot()
    {
        var result = new Dictionary<string, EnrichmentProviderSnapshot>(StringComparer.Ordinal);
        foreach (var entry in _providers)
        {
            var c = entry.Value;
            result[entry.Key] = new(Interlocked.Read(ref c.Success), Interlocked.Read(ref c.Unavailable),
                Interlocked.Read(ref c.Failed), Interlocked.Read(ref c.TimedOut), Interlocked.Read(ref c.Cancelled),
                Interlocked.Read(ref c.CacheHits), Interlocked.Read(ref c.TotalElapsedMs), Interlocked.Read(ref c.MaxElapsedMs));
        }
        return result;
    }
}
