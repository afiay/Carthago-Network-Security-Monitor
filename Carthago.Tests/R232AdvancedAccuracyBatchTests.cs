// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R232AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch231235Context.Sample(232);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch231235Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R232_MdnsServiceEnumerationBurstRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Twenty_Distinct_Parsed_Mdns_Ptr_Services_Match()
    {
        var rule = new R232_MdnsServiceEnumerationBurstRule(); var source = Sample().Source;
        for (int i = 0; i < 19; i++)
        {
            var r = Sample(); r.Source = source; r.DnsQname = "_service" + i + "._tcp.local";
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
        }
        var last = Sample(); last.Source = source; last.DnsQname = "_service19._tcp.local";
        Assert.True((await rule.EvaluateAsync(At(last, 19))).Matched);
    }
    [Fact] public async Task Single_Bonjour_Query_Is_Benign()
        => Assert.False(await Hit(Sample()));
    [Fact] public async Task Packet_Info_And_Port_Without_Typed_Mdns_Are_Rejected()
    {
        var r = Sample(); r.ApplicationProtocol = null; r.Info = "mDNS service enumeration";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task A_Record_Is_Not_Ptr_Service_Enumeration()
    {
        var r = Sample(); r.DnsQtype = "A";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Dns_Response_Is_Not_A_Query()
    {
        var r = Sample(); r.DnsIsResponse = true;
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Contradictory_Tcp_Transport_Is_Rejected()
    {
        var r = Sample(); r.IsTcp = true;
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Qname_Does_Not_Inflate_Distinct_Services()
    {
        var rule = new R232_MdnsServiceEnumerationBurstRule(); var source = Sample().Source;
        for (int i = 0; i < 25; i++)
        {
            var r = Sample(); r.Source = source; r.DnsQname = "_http._tcp.local";
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
        }
    }
    [Fact] public async Task Service_Name_Is_Redacted_From_Evidence()
    {
        var rule = new R232_MdnsServiceEnumerationBurstRule(); var source = Sample().Source;
        RuleEvaluationResult? last = null;
        for (int i = 0; i < 20; i++)
        {
            var r = Sample(); r.Source = source; r.DnsQname = "_private" + i + "._tcp.local";
            last = await rule.EvaluateAsync(At(r, i));
        }
        Assert.True(last!.Matched);
        var evt = Assert.Single(last.Events);
        Assert.DoesNotContain("_private19", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains("_private19", StringComparison.Ordinal));
    }
    [Fact] public void Original_Shadow_And_Confidence_Floor()
    {
        var p = new R232_MdnsServiceEnumerationBurstRule().PrecisionProfile;
        Assert.Equal(76, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }
}
