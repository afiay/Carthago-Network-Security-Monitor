// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Dns;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R097AdvancedAccuracyBatchTests
{
    private readonly R097_ExcessiveUniqueSubdomainsRule _rule = new();
    private static string Label(int index) => "zx9q8v7m6n5p4t3k2" + index.ToString("D3");
    private async Task<RuleEvaluationResult> Query(int t, string qname, string source = "10.97.0.10")
        => await _rule.EvaluateAsync(NetworkBatch096100Context.Dns(t, qname, source: source));

    [Fact] public async Task TwentyFive_Distinct_Labels_Produce_Threshold_Evidence()
    {
        var root = NetworkBatch096100Context.UniqueRoot();
        RuleEvaluationResult? result = null;
        for (var i = 0; i < 25; i++) result = await Query(i, Label(i) + "." + root);
        Assert.True(result!.Matched);
        var e = Assert.Single(result.Events);
        Assert.Contains(e.StructuredEvidence!.Items, x => x.Key == "dns.uniqueSubdomains" && x.Value == "25");
        Assert.Contains(e.StructuredEvidence.Items, x => x.Key == "window_seconds" && x.Value == "300");
    }
    [Fact] public async Task Repeated_Same_Subdomain_Does_Not_Make_A_Burst()
    {
        var name = Label(0) + "." + NetworkBatch096100Context.UniqueRoot();
        for (var i = 0; i < 30; i++) Assert.False((await Query(i, name)).Matched);
    }
    [Fact] public async Task Different_Sources_Cannot_Combine_Their_Unique_Counts()
    {
        var root = NetworkBatch096100Context.UniqueRoot();
        for (var i = 0; i < 13; i++) Assert.False((await Query(i, Label(i) + "." + root, "10.97.0.11")).Matched);
        for (var i = 13; i < 25; i++) Assert.False((await Query(i, Label(i) + "." + root, "10.97.0.12")).Matched);
    }
    [Fact] public async Task Known_Telemetry_Root_And_Human_Readable_Name_Are_Benign()
    {
        Assert.False((await Query(1, "update.microsoft.com")).Matched);
        Assert.False((await Query(2, "www.example.com")).Matched);
    }
    [Fact] public async Task Invalid_Questions_Must_Not_Contaminate_The_Burst_State()
    {
        var root = NetworkBatch096100Context.UniqueRoot();
        for (var i = 0; i < 25; i++)
        {
            var c = NetworkBatch096100Context.Dns(i, Label(i) + "." + root);
            c.Record.HttpMethod = "GET";
            Assert.False((await _rule.EvaluateAsync(c)).Matched);
        }
        for (var i = 0; i < 24; i++) Assert.False((await Query(30 + i, Label(i) + "." + root)).Matched);
        Assert.True((await Query(55, Label(24) + "." + root)).Matched);
    }
    [Fact] public async Task Old_Observations_Expire_From_Five_Minute_Window()
    {
        var root = NetworkBatch096100Context.UniqueRoot();
        for (var i = 0; i < 24; i++) Assert.False((await Query(i, Label(i) + "." + root)).Matched);
        Assert.False((await Query(500, Label(24) + "." + root)).Matched);
    }
    [Fact] public async Task Dns_Response_And_Missing_Source_Are_Not_Subdomain_Queries()
    {
        var root = NetworkBatch096100Context.UniqueRoot();
        var c = NetworkBatch096100Context.Dns(1, Label(0) + "." + root, response: true);
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c = NetworkBatch096100Context.Dns(2, Label(1) + "." + root);
        c.Record.Source = null;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Cancellation_Precedes_State_Mutation()
    {
        using var cts = new CancellationTokenSource(); cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await _rule.EvaluateAsync(NetworkBatch096100Context.Dns(1, Label(1) + "." + NetworkBatch096100Context.UniqueRoot()), cts.Token));
    }
}
