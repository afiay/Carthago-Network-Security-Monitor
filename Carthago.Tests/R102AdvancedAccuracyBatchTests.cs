// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Dns;
using Xunit;
namespace Carthago.Tests;

[Collection("R102 distinct TXT correlation")]
public sealed class R102AdvancedAccuracyBatchTests
{
    private readonly R102_DNSTunnelingViaLongLabelsRule _rule=new();
    private static string Query()=>NetworkBatch101105Context.EncodedLabel+"."+NetworkBatch101105Context.Root();
    private async Task<bool> Hit(int t,string query,string type="TXT")
        =>(await _rule.EvaluateAsync(NetworkBatch101105Context.Dns(t,query,type:type))).Matched;
    [Fact] public async Task Structured_Long_HighEntropy_Txt_Query_Is_Candidate()
    {
        var e=Assert.Single((await _rule.EvaluateAsync(NetworkBatch101105Context.Dns(1,Query(),type:"TXT"))).Events);
        Assert.Equal("R102",e.RuleId);
        Assert.Contains(e.StructuredEvidence!.Items,x=>x.Key=="dns.longestLabelEntropy");
    }
    [Fact] public async Task Structured_Txt_Without_Transport_Identity_Fails_Closed()
    {
        // A DNS protocol label and qname alone do not establish UDP/TCP.
        // This uses new synthetic data, never frozen evaluation fixtures.
        var query = Query();
        var unknownTransport = NetworkBatch101105Context.Dns(52, query, type:"TXT");
        unknownTransport.Record.IsUdp = false;
        unknownTransport.Record.IsTcp = false;
        var missing = await _rule.EvaluateAsync(unknownTransport);
        Assert.False(missing.Matched);
        Assert.Empty(missing.Events);

        // Explicitly attributed UDP in an independently created record
        // remains eligible for R102 candidate classification.
        var attributedUdp = NetworkBatch101105Context.Dns(53, query, type:"TXT");
        var valid = await _rule.EvaluateAsync(attributedUdp);
        Assert.True(valid.Matched);
        Assert.Single(valid.Events);
    }

    [Fact] public async Task Monolithic_Long_Txt_Label_Remains_Recognized()
    {Assert.True(await Hit(1,new string('a',55)+"."+NetworkBatch101105Context.Root()));}
    [Fact] public async Task Benign_Short_Queries_Do_Not_Accumulate_Suspicious_Count()
    {
        var root=NetworkBatch101105Context.Root();
        for(var i=0;i<5;i++)Assert.False(await Hit(i,"portal."+root));
    }
    [Fact] public async Task Long_A_Query_Below_SingleEvent_Context_Threshold_Does_Not_Alert()
    {Assert.False(await Hit(1,NetworkBatch101105Context.EncodedLabel+"."+NetworkBatch101105Context.Root(),type:"A"));}
    [Fact] public async Task Same_Packet_Id_Cannot_Inflate_Burst_Or_Distinct_Evidence()
    {
        var c=NetworkBatch101105Context.Dns(1,Query(),type:"TXT");
        Assert.True((await _rule.EvaluateAsync(c)).Matched);
        for(var i=0;i<4;i++)Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Contradictory_Response_And_Invalid_Label_Are_NonEvidence()
    {
        var c=NetworkBatch101105Context.Dns(1,Query(),type:"TXT",response:true);
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        Assert.False(await Hit(2,"bad.."+Query()));
    }
    [Fact] public async Task Cancellation_And_Info_Only_Keyword_Do_Not_Mutate_State()
    {
        using var cts=new CancellationTokenSource();cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch101105Context.Dns(1,Query(),type:"TXT"),cts.Token));
        var c=NetworkBatch101105Context.Dns(2,"normal."+NetworkBatch101105Context.Root(),type:"TXT");
        c.Record.Info=Query();
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
}
