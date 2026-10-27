// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules.CloudSaas;
using Xunit;
namespace Carthago.Tests;
public sealed class R108AdvancedAccuracyBatchTests
{
    private readonly R108_ExcessiveUploadRatioPerHostRule _r=new();
    private static class C
    {
        internal static string Source()=>NetworkBatch106110Context.Source();
        internal static Carthago.Engine.Rules.RuleEvaluationContext Http(int t,string src,string host="mega.nz",string method="POST",int bytes=1200000,string uri="/upload",string process="curl.exe",string? info=null)=>NetworkBatch106110Context.Http(t,src,host,method,bytes,uri,process,info);
        internal static Carthago.Engine.Rules.RuleEvaluationContext Sweep(int t,string src,int dest)=>NetworkBatch106110Context.Sweep(t,src,dest);
        internal static Carthago.Engine.Rules.RuleEvaluationContext Inbound(int t,string src)=>NetworkBatch106110Context.Inbound(t,src);
    }
    [Fact] public async Task Outbound_Only_Ratio_Produces_Evidence()
    {
        var r=await _r.EvaluateAsync(C.Http(1,C.Source(),bytes:13000000));Assert.True(r.Matched);Assert.Contains(Assert.Single(r.Events).StructuredEvidence!.Items,x=>x.Key=="cloud.outboundBytes");
    }
    [Fact] public async Task Balanced_Inbound_Outbound_Is_Benign()
    {
        var s=C.Source();Assert.False((await _r.EvaluateAsync(C.Inbound(1,s))).Matched);Assert.False((await _r.EvaluateAsync(C.Http(2,s,bytes:13000000))).Matched);
    }
    [Fact] public async Task Small_Upload_Is_Below_Floor()
    {
        Assert.False((await _r.EvaluateAsync(C.Http(1,C.Source(),bytes:300000))).Matched);
    }
    [Fact] public async Task Replayed_Id_Cannot_Inflate_Ratio()
    {
        var s=C.Source();var c=C.Http(1,s,bytes:7000000);for(int i=0;i<8;i++)Assert.False((await _r.EvaluateAsync(c)).Matched);Assert.True((await _r.EvaluateAsync(C.Http(2,s,bytes:7000000))).Matched);
    }
    [Fact] public async Task Sni_And_Transport_Contradictions_Rejected()
    {
        var s=C.Source();var c=C.Http(1,s,bytes:13000000);c.Record.Sni="other.example";Assert.False((await _r.EvaluateAsync(c)).Matched);c=C.Http(2,s,bytes:13000000);c.Record.IsUdp=true;Assert.False((await _r.EvaluateAsync(c)).Matched);
    }
}
