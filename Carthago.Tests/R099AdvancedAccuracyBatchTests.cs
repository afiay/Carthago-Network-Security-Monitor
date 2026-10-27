// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Dns;
using Carthago.Services.Baseline;
using Xunit;
namespace Carthago.Tests;
public sealed class R099AdvancedAccuracyBatchTests
{
    private readonly R099_DNSQueryToNewlyRegisteredDomainRule _rule = new();
    private static string Novel() => "risk" + Guid.NewGuid().ToString("N")[..10] + ".example";
    private static Carthago.Engine.Rules.RuleEvaluationContext Context(int t, string qname, int ageDays = 1, int? score = 82)
    {
        var c = NetworkBatch096100Context.Dns(t, qname);
        c.Record.ReputationLastSeen = c.TimestampUtc.AddDays(-ageDays);
        c.Record.ReputationScore = score;
        return c;
    }
    [Fact] public async Task Recent_Reputation_Observation_And_Persisted_Baseline_Match()
    {
        var dir = Path.Combine(Path.GetTempPath(), "r099-batch-" + Guid.NewGuid().ToString("N"));
        try
        {
            using (BaselineStore.UseScoped(new BaselineStore(new BaselineOptions { DirectoryPath = dir })))
            {
                var e = Assert.Single((await _rule.EvaluateAsync(Context(1, Novel()))).Events);
                Assert.Contains(e.StructuredEvidence!.Items, x => x.Key == "reputation.lastSeenDays" && x.Value == "1.0");
                Assert.Contains(e.StructuredEvidence.Items, x => x.Key == "baseline.reason");
            }
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
    }
    [Fact] public async Task Missing_And_Older_Reputation_Observations_Are_Not_Evidence()
    {
        var c = Context(1, Novel()); c.Record.ReputationLastSeen = null;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        Assert.False((await _rule.EvaluateAsync(Context(2, Novel(), ageDays: 8))).Matched);
    }
    [Fact] public async Task Future_Reputation_Time_Cannot_Masquerade_As_Zero_Days_Old()
    {
        var c = Context(1, Novel());
        c.Record.ReputationLastSeen = c.TimestampUtc.AddMinutes(1);
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Invalid_Reputation_Scores_Are_Rejected()
    {
        Assert.False((await _rule.EvaluateAsync(Context(1, Novel(), score: -1))).Matched);
        Assert.False((await _rule.EvaluateAsync(Context(2, Novel(), score: 101))).Matched);
    }
    [Fact] public async Task No_Dns_Question_And_Http_Contamination_Are_NonEvidence()
    {
        var c = Context(1, Novel()); c.Record.DnsQname = null; c.Record.Info = "newly registered malicious domain";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c = Context(2, Novel()); c.Record.HttpMethod = "GET";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Baseline_Persistence_Failure_Must_Fail_Closed()
    {
        var file = Path.GetTempFileName();
        try
        {
            using (BaselineStore.UseScoped(new BaselineStore(new BaselineOptions { DirectoryPath = file })))
                Assert.False((await _rule.EvaluateAsync(Context(1, Novel()))).Matched);
        }
        finally { File.Delete(file); }
    }
    [Fact] public async Task Repeated_Older_But_Recent_Domain_Is_Suppressed_After_Three_Observations()
    {
        var dir = Path.Combine(Path.GetTempPath(), "r099-known-" + Guid.NewGuid().ToString("N"));
        try
        {
            using (BaselineStore.UseScoped(new BaselineStore(new BaselineOptions { DirectoryPath = dir })))
            {
                var q = Novel();
                Assert.True((await _rule.EvaluateAsync(Context(1, q, ageDays: 4))).Matched);
                Assert.True((await _rule.EvaluateAsync(Context(2, q, ageDays: 4))).Matched);
                Assert.False((await _rule.EvaluateAsync(Context(3, q, ageDays: 4))).Matched);
            }
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
    }
    [Fact] public async Task Cancellation_Stops_Evaluation()
    {
        using var cts = new CancellationTokenSource(); cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await _rule.EvaluateAsync(Context(1, Novel()), cts.Token));
    }
}
