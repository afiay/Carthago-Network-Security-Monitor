// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;
namespace Carthago.Tests;

[Collection("Legacy rules R011-R015 isolated")]
public sealed class R045AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R045_SparseHeaderPostToInternetRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 7, 0, 0, DateTimeKind.Utc);
    public R045AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int seconds=0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(seconds)));

    private static TrafficRecord Post(string headers="Host: upload.example.org\r\nUser-Agent: uploader/1\r\n\r\n",
        string dst="8.8.8.8")
        => new(){Source="10.45.0.2",Destination=dst,Protocol="HTTP",DestinationPort=80,
            HttpMethod="POST",HttpRequestHeaders=headers,HttpHost="upload.example.org",Length=200};
    [Fact] public async Task Complete_Post_With_Missing_Content_Type_Matches()
    {
        var e=Assert.Single((await See(Post())).Events);
        Assert.Equal("R045",e.RuleId);Assert.Contains("Content-Type",e.Description);
    }
    [Fact] public async Task Complete_Post_With_Missing_User_Agent_Matches()
    {
        var r=Post("Host: upload.example.org\r\nContent-Type: application/json\r\n\r\n");
        var e=Assert.Single((await See(r)).Events);
        Assert.Contains("User-Agent",e.Description);
    }
    [Fact] public async Task Complete_Normal_Post_With_Both_Headers_Does_Not_Match()
    {
        var r=Post("Host: upload.example.org\r\nUser-Agent: browser\r\nContent-Type: application/json\r\n\r\n");
        Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Incomplete_Or_Absent_Headers_Cannot_Prove_Sparsity()
    {
        var r=Post("Host: upload.example.org\r\nUser-Agent: browser\r\n");
        Assert.False((await See(r)).Matched);
        r=Post("");Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Missing_Duplicate_Or_Contradictory_Host_Is_Excluded()
    {
        var r=Post("User-Agent: browser\r\n\r\n");
        Assert.False((await See(r)).Matched);
        r=Post("Host: upload.example.org\r\nHost: other.example.net\r\n\r\n");
        Assert.False((await See(r)).Matched);
        r=Post("Host: other.example.net\r\n\r\n");
        Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Wrong_Method_Protocol_And_Info_Only_Evidence_Is_Excluded()
    {
        var r=Post();r.HttpMethod="GET";Assert.False((await See(r)).Matched);
        r=Post();r.Protocol="SMTP";Assert.False((await See(r)).Matched);
        r=Post();r.HttpRequestHeaders=null;r.Info="POST / HTTP/1.1\r\nHost: upload.example.org\r\n";
        Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Public_Attribution_And_Privacy_Are_Enforced()
    {
        Assert.False((await See(Post(dst:"203.0.113.3"))).Matched);
        var e=Assert.Single((await See(Post())).Events);
        Assert.DoesNotContain("upload.example.org",e.Description);
    }
    [Fact] public async Task Repeated_Sparse_Post_Is_Suppressed()
    {
        Assert.True((await See(Post())).Matched);
        Assert.True((await See(Post(),1)).Suppressed);
    }
}
