// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Dns;
using Xunit;
namespace Carthago.Tests;
public sealed class R096AdvancedAccuracyBatchTests
{
    private readonly R096_FastFluxDNSPatternRule _rule = new();
    private const string Six = "198.51.100.10 198.51.100.11 198.51.100.12 198.51.100.13 198.51.100.14 198.51.100.15";
    private async Task<bool> Hit(int t, string answers = Six, int? ttl = 30, bool response = true, string qtype = "A")
        => (await _rule.EvaluateAsync(NetworkBatch096100Context.Dns(t, NetworkBatch096100Context.UniqueRoot(), response: response, answers: answers, ttl: ttl, qtype: qtype))).Matched;

    [Fact] public async Task Distinct_Address_Answers_With_Low_Ttl_Match()
    {
        var result = await _rule.EvaluateAsync(NetworkBatch096100Context.Dns(1, NetworkBatch096100Context.UniqueRoot(), response: true, answers: Six, ttl: 30));
        var e = Assert.Single(result.Events);
        Assert.Equal("R096", e.RuleId);
        Assert.Contains(e.StructuredEvidence!.Items, x => x.Key == "dns.answerCount" && x.Value == "6");
        Assert.Contains(e.StructuredEvidence.Items, x => x.Key == "dns.ttl" && x.Value == "30");
    }
    [Fact] public async Task Valid_Separated_A_Record_Tokens_Are_Countable()
    { Assert.True(await Hit(1, "A 198.51.100.10; A 198.51.100.11; A 198.51.100.12; A 198.51.100.13")); }
    [Fact] public async Task IPv6_Aaaa_Answers_Are_Countable_Only_As_IPv6()
    {
        Assert.True(await Hit(1, "2001:db8::1 2001:db8::2 2001:db8::3 2001:db8::4", qtype: "AAAA"));
        Assert.False(await Hit(2, "2001:db8::1 2001:db8::2 2001:db8::3 2001:db8::4", qtype: "A"));
    }
    [Fact] public async Task Duplicate_And_Malformed_Addresses_Cannot_Inflate_Answer_Count()
    {
        Assert.False(await Hit(1, "198.51.100.10 198.51.100.10 999.999.999.999 198.51.100.11"));
        Assert.False(await Hit(2, "1.2.3.4garbage 198.51.100.10 198.51.100.11"));
    }
    [Fact] public async Task Benign_High_Ttl_And_Missing_Ttl_Are_Excluded()
    { Assert.False(await Hit(1, ttl: 3600)); Assert.False(await Hit(2, ttl: null)); }
    [Fact] public async Task Dns_Query_Or_Wrong_Answer_Family_Is_Not_Fast_Flux_Evidence()
    { Assert.False(await Hit(1, response: false)); Assert.False(await Hit(2, qtype: "AAAA")); }
    [Fact] public async Task Contradictory_Http_Or_L4_Metadata_Is_NonEvidence()
    {
        var c = NetworkBatch096100Context.Dns(1, NetworkBatch096100Context.UniqueRoot(), response: true, answers: Six, ttl: 30);
        c.Record.HttpMethod = "GET";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c = NetworkBatch096100Context.Dns(2, NetworkBatch096100Context.UniqueRoot(), response: true, answers: Six, ttl: 30);
        c.Record.IsTcp = true;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c = NetworkBatch096100Context.Dns(3, NetworkBatch096100Context.UniqueRoot(), response: true, answers: Six, ttl: 30);
        c.Record.DnsQname = null;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c = NetworkBatch096100Context.Dns(4, NetworkBatch096100Context.UniqueRoot(), response: true, answers: Six, ttl: 30);
        c.Record.DnsRcode = "NXDOMAIN";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Missing_And_Oversized_Answer_Fields_Fail_Closed()
    { Assert.False(await Hit(1, answers: "")); Assert.False(await Hit(2, answers: Six + new string('x', 2100))); }
    [Fact] public async Task Cancellation_Is_Observed_Before_Any_Detection()
    {
        using var cts = new CancellationTokenSource(); cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await _rule.EvaluateAsync(NetworkBatch096100Context.Dns(1, NetworkBatch096100Context.UniqueRoot(), response: true, answers: Six, ttl: 30), cts.Token));
    }
}
