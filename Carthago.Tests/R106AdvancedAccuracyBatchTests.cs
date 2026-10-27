// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules.CloudSaas;
using Xunit;
namespace Carthago.Tests;
public sealed class R106AdvancedAccuracyBatchTests
{
    private readonly R106_UploadAfterInternalSweepRule _r=new();
    private static class C
    {
        internal static string Source()=>NetworkBatch106110Context.Source();
        internal static Carthago.Engine.Rules.RuleEvaluationContext Http(int t,string src,string host="mega.nz",string method="POST",int bytes=1200000,string uri="/upload",string process="curl.exe",string? info=null)=>NetworkBatch106110Context.Http(t,src,host,method,bytes,uri,process,info);
        internal static Carthago.Engine.Rules.RuleEvaluationContext Sweep(int t,string src,int dest)=>NetworkBatch106110Context.Sweep(t,src,dest);
        internal static Carthago.Engine.Rules.RuleEvaluationContext Inbound(int t,string src)=>NetworkBatch106110Context.Inbound(t,src);
    }
    [Fact] public async Task Four_Target_Sweep_Then_Upload()
    {
        var s=C.Source();for(int i=1;i<=4;i++)Assert.False((await _r.EvaluateAsync(C.Sweep(i,s,i))).Matched);var r=await _r.EvaluateAsync(C.Http(6,s,bytes:3000000));Assert.True(r.Matched);Assert.Contains(Assert.Single(r.Events).StructuredEvidence!.Items,x=>x.Key=="sweep.distinctTargets"&&x.Value=="4");
    }
    [Fact] public async Task Three_Target_Sweep_Is_Insufficient()
    {
        var s=C.Source();for(int i=1;i<=3;i++)await _r.EvaluateAsync(C.Sweep(i,s,i));Assert.False((await _r.EvaluateAsync(C.Http(6,s,bytes:3000000))).Matched);
    }
    [Fact] public async Task Expired_Sweep_Is_Not_Reused()
    {
        var s=C.Source();for(int i=1;i<=4;i++)await _r.EvaluateAsync(C.Sweep(i,s,i));Assert.False((await _r.EvaluateAsync(C.Http(1300,s,bytes:3000000))).Matched);
    }
    [Fact] public async Task Info_Only_Probe_Is_Not_Sweep()
    {
        var s=C.Source();for(int i=1;i<=4;i++){var c=C.Sweep(i,s,i);c.Record.DestinationPort=8080;c.Record.Info="SMB admin sweep";await _r.EvaluateAsync(c);}Assert.False((await _r.EvaluateAsync(C.Http(6,s,bytes:3000000))).Matched);
    }
    [Fact] public async Task Download_And_Contradictory_Sni_Are_Rejected()
    {
        var s=C.Source();for(int i=1;i<=4;i++)await _r.EvaluateAsync(C.Sweep(i,s,i));Assert.False((await _r.EvaluateAsync(C.Http(6,s,method:"GET",bytes:10000000))).Matched);var c=C.Http(7,s,bytes:10000000);c.Record.Sni="other.example";Assert.False((await _r.EvaluateAsync(c)).Matched);
    }
}
