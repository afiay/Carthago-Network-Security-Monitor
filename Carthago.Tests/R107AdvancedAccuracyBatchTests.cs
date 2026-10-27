// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules.CloudSaas;
using Xunit;
namespace Carthago.Tests;
public sealed class R107AdvancedAccuracyBatchTests
{
    private readonly R107_ExfiltrationSplitAcrossManyDestinationsRule _r=new();
    private static class C
    {
        internal static string Source()=>NetworkBatch106110Context.Source();
        internal static Carthago.Engine.Rules.RuleEvaluationContext Http(int t,string src,string host="mega.nz",string method="POST",int bytes=1200000,string uri="/upload",string process="curl.exe",string? info=null)=>NetworkBatch106110Context.Http(t,src,host,method,bytes,uri,process,info);
        internal static Carthago.Engine.Rules.RuleEvaluationContext Sweep(int t,string src,int dest)=>NetworkBatch106110Context.Sweep(t,src,dest);
        internal static Carthago.Engine.Rules.RuleEvaluationContext Inbound(int t,string src)=>NetworkBatch106110Context.Inbound(t,src);
    }
    [Fact] public async Task Six_Distinct_Upload_Destinations()
    {
        var s=C.Source();for(int i=1;i<=5;i++){var c=C.Http(i,s);c.Record.Destination="198.51.100."+i;Assert.False((await _r.EvaluateAsync(c)).Matched);}var last=C.Http(6,s);last.Record.Destination="198.51.100.6";var r=await _r.EvaluateAsync(last);Assert.True(r.Matched);Assert.Contains(Assert.Single(r.Events).StructuredEvidence!.Items,x=>x.Key=="cloud.distinctDestinations"&&x.Value=="6");
    }
    [Fact] public async Task Download_Fanout_Is_Benign()
    {
        var s=C.Source();for(int i=1;i<=8;i++){var c=C.Http(i,s,method:"GET",bytes:2000000);c.Record.Destination="198.51.100."+i;Assert.False((await _r.EvaluateAsync(c)).Matched);}
    }
    [Fact] public async Task One_Destination_Does_Not_Qualify()
    {
        var s=C.Source();for(int i=1;i<=10;i++)Assert.False((await _r.EvaluateAsync(C.Http(i,s))).Matched);
    }
    [Fact] public async Task Replayed_Id_Does_Not_Inflate_Window()
    {
        var s=C.Source();var c=C.Http(1,s,bytes:2500000);for(int i=0;i<10;i++)Assert.False((await _r.EvaluateAsync(c)).Matched);for(int i=2;i<=4;i++){var next=C.Http(i,s);next.Record.Destination="198.51.100."+i;Assert.False((await _r.EvaluateAsync(next)).Matched);}
    }
    [Fact] public async Task Info_Only_And_Sni_Conflict_Rejected()
    {
        var s=C.Source();var c=C.Http(1,s,method:"GET",info:"POST upload");Assert.False((await _r.EvaluateAsync(c)).Matched);c=C.Http(2,s);c.Record.Sni="other.example";Assert.False((await _r.EvaluateAsync(c)).Matched);
    }
}
