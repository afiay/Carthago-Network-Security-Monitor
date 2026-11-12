using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class EnrichmentProviderHealthTests
{
    [Fact]
    public async Task Outcomes_And_Cache_Hits_Are_Recorded()
    {
        var health = new EnrichmentProviderHealth();
        var budget = TimeSpan.FromSeconds(5);
        var ok = await health.LookupAsync<string>("whois", _ => Task.FromResult<string?>("ok"), budget, default);
        var missing = await health.LookupAsync<string>("whois", _ => Task.FromResult<string?>(null), budget, default);
        var failed = await health.LookupAsync<string>("whois", _ => Task.FromException<string?>(new InvalidOperationException()), budget, default);
        health.RecordCacheHit("whois");
        Assert.Equal(EnrichmentLookupStatus.Success, ok.Status);
        Assert.Equal(EnrichmentLookupStatus.Unavailable, missing.Status);
        Assert.Equal(EnrichmentLookupStatus.Failed, failed.Status);
        var stats = health.Snapshot()["whois"];
        Assert.Equal(1L, stats.Success);
        Assert.Equal(1L, stats.Unavailable);
        Assert.Equal(1L, stats.Failed);
        Assert.Equal(1L, stats.CacheHits);
    }

    [Fact]
    public async Task Deadline_Discards_Late_Result()
    {
        var health = new EnrichmentProviderHealth();
        var late = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var result = await health.LookupAsync<string>("vpn-proxy", _ => late.Task, TimeSpan.FromMilliseconds(30), default);
        Assert.Equal(EnrichmentLookupStatus.TimedOut, result.Status);
        Assert.Null(result.Value);
        late.SetResult("late");
        Assert.Null(result.Value);
        Assert.Equal(1L, health.Snapshot()["vpn-proxy"].TimedOut);
    }

    [Fact]
    public async Task Session_Cancellation_Is_Not_A_Timeout()
    {
        var health = new EnrichmentProviderHealth();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        bool invoked = false;
        var result = await health.LookupAsync<string>("reputation", _ =>
        {
            invoked = true;
            return Task.FromResult<string?>("unexpected");
        }, TimeSpan.FromSeconds(5), cts.Token);
        Assert.False(invoked);
        Assert.Equal(EnrichmentLookupStatus.Cancelled, result.Status);
        Assert.Equal(1L, health.Snapshot()["reputation"].Cancelled);
    }
}
