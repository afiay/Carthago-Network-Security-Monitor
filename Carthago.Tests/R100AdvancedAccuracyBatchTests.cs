// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Dns;
using Xunit;
namespace Carthago.Tests;
public sealed class R100AdvancedAccuracyBatchTests
{
    private readonly R100_DNSQueryForInternalNameToExternalResolverRule _rule = new();
    private static string InternalName() => "dc" + Guid.NewGuid().ToString("N")[..8] + ".corp";
    private async Task<bool> Hit(int t, string query, string source = "10.100.0.10", string resolver = "8.8.8.8")
        => (await _rule.EvaluateAsync(NetworkBatch096100Context.Dns(t, query, source: source, destination: resolver))).Matched;

    [Fact] public async Task Three_Distinct_Queries_To_Public_Resolver_Trigger_Leak_Evidence()
    {
        var name = InternalName();
        Assert.False(await Hit(1, name));
        Assert.False(await Hit(2, name));
        var result = await _rule.EvaluateAsync(NetworkBatch096100Context.Dns(3, name, source: "10.100.0.10"));
        var e = Assert.Single(result.Events);
        Assert.Equal("R100", e.RuleId);
        Assert.Contains(e.StructuredEvidence!.Items, x => x.Key == "resolver.destination" && x.Value == "8.8.8.8");
        Assert.Contains(e.StructuredEvidence.Items, x => x.Key == "count" && x.Value == "3");
    }
    [Fact] public async Task Single_Label_Internal_Printer_Query_Is_Supported()
    {
        var name = "printer" + Guid.NewGuid().ToString("N")[..6];
        Assert.False(await Hit(1, name));
        Assert.False(await Hit(2, name));
        Assert.True(await Hit(3, name));
    }
    [Fact] public async Task Wpad_Fallback_Requires_Five_Independent_Queries()
    {
        var source = "10.100.1." + (10 + Guid.NewGuid().ToByteArray()[0] % 50);
        for (var i = 0; i < 4; i++) Assert.False(await Hit(i, "wpad", source: source));
        Assert.True(await Hit(5, "wpad", source: source));
    }
    [Fact] public async Task Same_Record_Id_Replay_Does_Not_Inflate_Threshold()
    {
        var c = NetworkBatch096100Context.Dns(1, InternalName());
        for (var i = 0; i < 6; i++) Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Private_Resolver_And_NonPublic_Address_Space_Are_Not_External()
    {
        var name = InternalName();
        foreach (var destination in new[] { "192.168.1.53", "100.64.0.10", "198.51.100.20", "203.0.113.20", "224.0.0.251" })
            Assert.False(await Hit(1, name, resolver: destination));
    }
    [Fact] public async Task External_Client_And_Hostname_Resolver_Do_Not_Prove_Internal_Leak()
    {
        var name = InternalName();
        Assert.False(await Hit(1, name, source: "198.51.100.10"));
        Assert.False(await Hit(2, name, resolver: "dns.google"));
    }
    [Fact] public async Task Distinct_Resolvers_Do_Not_Combine_Their_Windows()
    {
        var name = InternalName();
        Assert.False(await Hit(1, name));
        Assert.False(await Hit(2, name));
        Assert.False(await Hit(3, name, resolver: "1.1.1.1"));
    }
    [Fact] public async Task Old_Queries_Expire_And_OneOff_Public_Names_Are_Ignored()
    {
        var name = InternalName();
        Assert.False(await Hit(1, name));
        Assert.False(await Hit(2, name));
        Assert.False(await Hit(900, name));
        Assert.False(await Hit(901, "www.example.com"));
    }
    [Fact] public async Task Response_And_Contradictory_Transport_Cannot_Accumulate_Leak_State()
    {
        var name = InternalName();
        var c = NetworkBatch096100Context.Dns(1, name, response: true);
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c = NetworkBatch096100Context.Dns(2, name);
        c.Record.IsTcp = true;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        Assert.False(await Hit(3, name));
    }
    [Fact] public async Task Cancellation_Prevents_Sequence_Mutation()
    {
        using var cts = new CancellationTokenSource(); cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await _rule.EvaluateAsync(NetworkBatch096100Context.Dns(1, InternalName()), cts.Token));
    }
}
