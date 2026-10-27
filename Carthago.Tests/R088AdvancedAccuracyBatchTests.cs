// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Payloads;
using Xunit;
namespace Carthago.Tests;
public sealed class R088AdvancedAccuracyBatchTests
{
    private readonly R088_SuspiciousDeserializationPayloadRule _rule=new();
    private const string Payload="/api?encoded=rO0ABAAAAAABBBBCC";
    private static Carthago.Engine.Rules.RuleEvaluationContext C(int t,string uri=Payload,
        string? service="DESERIALIZATION_PAYLOAD_OBSERVED",string? info=null)
    {
        var c=NetworkBatch081085Context.Http(t,uri,info:info);
        c.Record.ApplicationProtocol="HTTP";c.Record.ApplicationService=service;return c;
    }
    private async Task<bool> Seen(int t,string uri=Payload,string? svc="DESERIALIZATION_PAYLOAD_OBSERVED")
        =>(await _rule.EvaluateAsync(C(t,uri,svc))).Matched;
    [Fact] public async Task Parsed_Java_Serialization_Pattern_Matches()
    {Assert.True(await Seen(1));}
    [Fact] public async Task Recognized_DotNet_Deserializer_Tokens_Match_When_Classified()
    {Assert.True(await Seen(1,uri:"/api?type=ObjectDataProvider"));}
    [Fact] public async Task Legitimate_Serialization_Traffic_Without_Risky_Classifications_Does_Not_Match()
    {
        Assert.False(await Seen(1,svc:"HTTP_REQUEST"));
        Assert.False(await Seen(2,uri:"/docs?q=serialized-format"));
        Assert.False(await Seen(3,uri:"/docs?q=Object"));
    }
    [Fact] public async Task Log_Text_Or_Untrusted_Application_Labels_Are_Insufficient()
    {
        var c=C(1,"/api",service:"DESERIALIZATION_PAYLOAD_OBSERVED",info:"ysoserial rO0ABAAAAAABBBB");
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=C(2,service:"DESERIALIZATION_PAYLOAD_OBSERVED");c.Record.ApplicationProtocol="SSH";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Invalid_Http_Evidence_Does_Not_Match()
    {
        var c=C(1);c.Record.HttpMethod=null;Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=C(2);c.Record.IsQuic=true;Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=C(3);c.Record.HttpHost=null;Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=C(4);c.Record.HttpRequestHeaders="Host: wrong.example.test\r\n\r\n";Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Same_Record_Is_Not_Reported_More_Than_Once()
    {
        var c=C(1);Assert.True((await _rule.EvaluateAsync(c)).Matched);
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        Assert.True(await Seen(2));
    }
    [Fact] public async Task Cancellation_And_Payload_Secrets_Are_Redacted()
    {
        using var cts=new CancellationTokenSource();cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(C(1),cts.Token));
        var e=Assert.Single((await _rule.EvaluateAsync(C(2,Payload+"&secret88=token"))).Events);
        Assert.DoesNotContain("secret88",e.Description);Assert.DoesNotContain("secret88",e.Evidence);
    }
}
