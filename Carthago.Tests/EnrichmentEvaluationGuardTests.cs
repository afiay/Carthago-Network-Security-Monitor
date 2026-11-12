using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class EnrichmentEvaluationGuardTests
{
    [Fact]
    public async Task Successful_Enrichment_Evaluates_Once()
    {
        int evaluated = 0, failed = 0;
        await EnrichmentEvaluationGuard.RunAsync(() => Task.CompletedTask,
            () => evaluated++, _ => failed++, CancellationToken.None);
        Assert.Equal(1, evaluated);
        Assert.Equal(0, failed);
    }

    [Fact]
    public async Task Provider_Failure_Still_Evaluates_Once()
    {
        int evaluated = 0, failed = 0;
        await EnrichmentEvaluationGuard.RunAsync(
            () => Task.FromException(new InvalidOperationException("provider unavailable")),
            () => evaluated++, _ => failed++, CancellationToken.None);
        Assert.Equal(1, evaluated);
        Assert.Equal(1, failed);
    }

    [Fact]
    public async Task Provider_Timeout_Is_Not_Session_Cancellation()
    {
        int evaluated = 0, failed = 0;
        await EnrichmentEvaluationGuard.RunAsync(
            () => Task.FromException(new OperationCanceledException("provider timeout")),
            () => evaluated++, _ => failed++, CancellationToken.None);
        Assert.Equal(1, evaluated);
        Assert.Equal(1, failed);
    }

    [Fact]
    public async Task Session_Cancellation_Does_Not_Evaluate()
    {
        using var cts = new CancellationTokenSource();
        int evaluated = 0, failed = 0;
        await EnrichmentEvaluationGuard.RunAsync(() =>
        {
            cts.Cancel();
            return Task.FromCanceled(cts.Token);
        }, () => evaluated++, _ => failed++, cts.Token);
        Assert.Equal(0, evaluated);
        Assert.Equal(0, failed);
    }

    [Fact]
    public async Task Already_Cancelled_Session_Does_Not_Start_Enrichment()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        int enriched = 0, evaluated = 0;
        await EnrichmentEvaluationGuard.RunAsync(() =>
        {
            enriched++;
            return Task.CompletedTask;
        }, () => evaluated++, _ => { }, cts.Token);
        Assert.Equal(0, enriched);
        Assert.Equal(0, evaluated);
    }
}
