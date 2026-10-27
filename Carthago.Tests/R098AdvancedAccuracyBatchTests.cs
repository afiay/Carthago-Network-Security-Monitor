// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Dns;
using Carthago.Services.Baseline;
using Xunit;
namespace Carthago.Tests;
public sealed class R098AdvancedAccuracyBatchTests
{
    private readonly R098_SuspiciousDynamicDNSProviderRule _rule = new();
    private static string RandomName() => "x8q7v6m5n4p3" + Guid.NewGuid().ToString("N")[..6] + ".duckdns.org";
    private async Task<bool> Hit(int t, string query, string qtype = "A")
        => (await _rule.EvaluateAsync(NetworkBatch096100Context.Dns(t, query, qtype: qtype))).Matched;

    [Fact] public async Task Random_DynamicDns_Label_Is_Detected()
    {
        var dir = Path.Combine(Path.GetTempPath(), "r098-batch-" + Guid.NewGuid().ToString("N"));
        try
        {
            using (BaselineStore.UseScoped(new BaselineStore(new BaselineOptions { DirectoryPath = dir })))
            {
                var e = Assert.Single((await _rule.EvaluateAsync(NetworkBatch096100Context.Dns(1, RandomName()))).Events);
                Assert.Contains(e.StructuredEvidence!.Items, x => x.Key == "dns.dynamicProvider" && x.Value == "duckdns.org");
                Assert.Contains(e.StructuredEvidence.Items, x => x.Key == "baseline.reason");
            }
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
    }
    [Fact] public async Task Common_Human_Readable_Nas_Label_Does_Not_Trigger()
    { Assert.False(await Hit(1, "mynas.duckdns.org")); Assert.False(await Hit(2, "nas.ddns.net")); }
    [Fact] public async Task Provider_Lookalike_And_Substring_Are_Not_Provider_Proof()
    {
        Assert.False(await Hit(1, "x8q7v6m5n4p3.evilduckdns.org"));
        Assert.False(await Hit(2, "x8q7v6m5n4p3.duckdns.org.evil.example"));
    }
    [Fact] public async Task Duplicate_Record_Id_Does_Not_Inflate_Repeat_Window()
    {
        var q = RandomName();
        var c = NetworkBatch096100Context.Dns(1, q);
        var first = Assert.Single((await _rule.EvaluateAsync(c)).Events);
        var duplicate = Assert.Single((await _rule.EvaluateAsync(c)).Events);
        Assert.Contains(first.StructuredEvidence!.Items, x => x.Key == "count" && x.Value == "1");
        Assert.Contains(duplicate.StructuredEvidence!.Items, x => x.Key == "count" && x.Value == "1");
        var next = Assert.Single((await _rule.EvaluateAsync(NetworkBatch096100Context.Dns(2, q))).Events);
        Assert.Contains(next.StructuredEvidence!.Items, x => x.Key == "count" && x.Value == "2");
    }
    [Fact] public async Task TxtLike_Long_LowEntropy_Label_Needs_Repetition_For_High_Severity()
    {
        var q = "aaaaaaaaaaaa.duckdns.org";
        var dir = Path.Combine(Path.GetTempPath(), "r098-repeat-" + Guid.NewGuid().ToString("N"));
        try
        {
            using (BaselineStore.UseScoped(new BaselineStore(new BaselineOptions { DirectoryPath = dir })))
            {
                var first = await _rule.EvaluateAsync(NetworkBatch096100Context.Dns(1, q, qtype: "TXT"));
                var second = await _rule.EvaluateAsync(NetworkBatch096100Context.Dns(2, q, qtype: "TXT"));
                Assert.True(first.Matched);
                Assert.True(second.Matched);
                Assert.Contains(Assert.Single(second.Events).StructuredEvidence!.Items, x => x.Key == "count" && x.Value == "2");
            }
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
    }
    [Fact] public async Task Contradictory_Dns_Http_And_Response_Fields_Are_NonEvidence()
    {
        var c = NetworkBatch096100Context.Dns(1, RandomName());
        c.Record.HttpUri = "/gate.php";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c = NetworkBatch096100Context.Dns(2, RandomName(), response: true);
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c = NetworkBatch096100Context.Dns(3, RandomName());
        c.Record.DnsQtype = null;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Expired_Repetition_Window_Is_Not_Resurrected()
    {
        var q = RandomName();
        await _rule.EvaluateAsync(NetworkBatch096100Context.Dns(1, q));
        var later = Assert.Single((await _rule.EvaluateAsync(NetworkBatch096100Context.Dns(1200, q))).Events);
        Assert.Contains(later.StructuredEvidence!.Items, x => x.Key == "count" && x.Value == "1");
    }
    [Fact] public async Task Cancellation_Is_Propagated()
    {
        using var cts = new CancellationTokenSource(); cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await _rule.EvaluateAsync(NetworkBatch096100Context.Dns(1, RandomName()), cts.Token));
    }
}
