// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R194AdvancedAccuracyBatchTests
{
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0) => NetworkBatch186195Context.At(r, seconds);
    private static TrafficRecord Q(string name, string type = "A") => NetworkBatch186195Context.Query(name, type);

    private static TrafficRecord Get(string host="resolver.example.net",string? path=null)
        => NetworkBatch186195Context.DohGet(host,path);
    [Fact] public async Task Typed_Get_Doh_Shape_On_Unapproved_Host_Qualifies()
        => Assert.True((await new R194_DohOverUncommonHostRule().EvaluateAsync(At(Get()))).Matched);
    [Fact] public async Task Typed_Post_Doh_Shape_Qualifies()
    {
        var r=Get();r.HttpMethod="POST";r.HttpUri="/custom-dns";r.HttpRequestHeaders="Host: resolver.example.net\r\nContent-Type: application/dns-message\r\nContent-Length: 32";
        Assert.True((await new R194_DohOverUncommonHostRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Approved_Public_Doh_Host_Suppressed()
        => Assert.False((await new R194_DohOverUncommonHostRule().EvaluateAsync(At(Get("dns.google")))).Matched);
    [Fact] public async Task DnsQuery_Lookalike_Path_Rejected()
        => Assert.False((await new R194_DohOverUncommonHostRule().EvaluateAsync(At(Get(path:"/dns-query-status?dns=AAABAAABAAAAAAAA")))).Matched);
    [Fact] public async Task Accept_Header_Alone_Not_Doh()
        => Assert.False((await new R194_DohOverUncommonHostRule().EvaluateAsync(At(Get(path:"/dns-query")))).Matched);
    [Fact] public async Task Truncated_Dns_Wire_Question_Not_Doh()
        => Assert.False((await new R194_DohOverUncommonHostRule().EvaluateAsync(At(Get(path:"/dns-query?dns=AAABAAABAAAAAAAA")))).Matched);
    [Fact] public async Task Missing_Dns_Mime_Not_Doh()
    {
        var r=Get();r.HttpRequestHeaders="Host: resolver.example.net";
        Assert.False((await new R194_DohOverUncommonHostRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Contradictory_Host_Header_Rejected()
    {
        var r=Get();r.HttpRequestHeaders="Host: different.example.net\r\nAccept: application/dns-message";
        Assert.False((await new R194_DohOverUncommonHostRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Packet_Id_Rejected()
    {
        var rule=new R194_DohOverUncommonHostRule();var r=Get();
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
    }
    [Fact] public async Task Sensitive_Doh_Query_And_Host_Redacted()
    {
        var x=await new R194_DohOverUncommonHostRule().EvaluateAsync(At(Get("secret194.example.net")));
        Assert.True(x.Matched);
        Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,e=>e.Value.Contains("secret194",StringComparison.Ordinal)
            || e.Value.Contains("AAABAAAB",StringComparison.Ordinal));
    }
    [Fact] public void Shadow_And_Floor_Preserved()
    {
        var p=new R194_DohOverUncommonHostRule().PrecisionProfile;
        Assert.Equal(74,p.MinimumConfidence);Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
