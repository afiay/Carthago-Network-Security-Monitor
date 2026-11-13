// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Contracts;
using Xunit;

namespace Carthago.Tests;

public sealed class ActiveServiceLifecycleTests
{
    private const string Sid = "S-1-5-21-100-200-300-1001";
    private const string Grant = "02702701-1234-4321-9999-000000000001";
    private static string Id => new('a', 64);
    private static string Json(string sid = Sid) => $"{{\"schemaVersion\":1,\"accountSid\":\"{sid}\",\"profiles\":[{{\"profileId\":\"{Id}\",\"grantId\":\"{Grant}\"}}]}}";
    private static ActiveServiceOptions Parse(string text) => ActiveServiceConfiguration.Parse(Encoding.UTF8.GetBytes(text));

    [Fact]
    public void ConfigPinsExactGrantAndAccount()
    {
        var config = Parse(Json());
        Assert.Equal(Sid, config.AccountSid);
        Assert.Equal(Guid.Parse(Grant), Assert.Single(config.Profiles).GrantId);
        Assert.Equal(Id, Assert.Single(config.Profiles).ProfileId);
    }
    [Theory]
    [InlineData("S-1-5-18")]
    [InlineData("S-1-5-19")]
    [InlineData("S-1-5-20")]
    public void BuiltInServiceAccountsRejected(string sid) => Assert.Throws<InvalidDataException>(() => Parse(Json(sid)));
    [Fact]
    public void StrictSchemaRejectsUnknownDuplicateAndEmptySelection()
    {
        Assert.Throws<InvalidDataException>(() => Parse(Json().Replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1")));
        Assert.Throws<InvalidDataException>(() => Parse(Json().Replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"password\":\"x\"")));
        Assert.Throws<InvalidDataException>(() => Parse(Json().Replace(Grant, Guid.Empty.ToString("D"))));
        Assert.Throws<InvalidDataException>(() => Parse($"{{\"schemaVersion\":1,\"accountSid\":\"{Sid}\",\"profiles\":[]}}"));
    }
    [Fact]
    public async Task FailedStartupNeverSignalsReadiness()
    {
        using var run = new ActiveServiceRun((_, _) => Task.FromResult(3));
        Assert.Equal(3, await run.Completion);
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.Started);
    }
    [Fact]
    public async Task CancellationWaitsForCleanup()
    {
        var cleanup = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancelled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var run = new ActiveServiceRun(async (token, ready) =>
        {
            ready();
            try { await Task.Delay(Timeout.Infinite, token); }
            catch (OperationCanceledException) { cancelled.TrySetResult(true); await cleanup.Task; return 130; }
            return 3;
        });
        try
        {
            await run.Started.WaitAsync(TimeSpan.FromSeconds(5));
            run.RequestStop();
            await cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.False(run.Completion.IsCompleted);
        }
        finally { run.RequestStop(); cleanup.TrySetResult(true); await run.Completion.WaitAsync(TimeSpan.FromSeconds(5)); }
        Assert.Equal(130, await run.Completion);
    }
    [Fact]
    public async Task NaturalExpiryCompletesWithoutRenewal()
    {
        using var run = new ActiveServiceRun((_, ready) => { ready(); return Task.FromResult(0); });
        await run.Started;
        Assert.Equal(0, await run.Completion);
    }
}
