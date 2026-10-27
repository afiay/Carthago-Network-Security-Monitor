// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules.CloudSaas;
using Xunit;
namespace Carthago.Tests;
public sealed class R110AdvancedAccuracyBatchTests
{
    private readonly R110_TelegramDiscordSlackAPIEgressRule _r=new();
    private static class C
    {
        internal static string Source()=>NetworkBatch106110Context.Source();
        internal static Carthago.Engine.Rules.RuleEvaluationContext Http(int t,string src,string host="mega.nz",string method="POST",int bytes=1200000,string uri="/upload",string process="curl.exe",string? info=null)=>NetworkBatch106110Context.Http(t,src,host,method,bytes,uri,process,info);
        internal static Carthago.Engine.Rules.RuleEvaluationContext Sweep(int t,string src,int dest)=>NetworkBatch106110Context.Sweep(t,src,dest);
        internal static Carthago.Engine.Rules.RuleEvaluationContext Inbound(int t,string src)=>NetworkBatch106110Context.Inbound(t,src);
    }
    [Fact] public async Task Telegram_Send_Has_Action_Evidence()
    {
        var r=await _r.EvaluateAsync(C.Http(1,C.Source(),host:"api.telegram.org",uri:"/botSECRET/sendDocument",bytes:250000));Assert.True(r.Matched);Assert.Contains(Assert.Single(r.Events).StructuredEvidence!.Items,x=>x.Key=="host.classifier");
    }
    [Fact] public async Task Generic_Collaboration_Is_Benign()
    {
        Assert.False((await _r.EvaluateAsync(C.Http(1,C.Source(),host:"slack.com",method:"GET",uri:"/client/home",bytes:1000000))).Matched);
    }
    [Fact] public async Task Get_Webhook_Is_Not_Send()
    {
        Assert.False((await _r.EvaluateAsync(C.Http(1,C.Source(),host:"hooks.slack.com",method:"GET",uri:"/services/A/B/C",bytes:1000000))).Matched);
    }
    [Fact] public async Task Packet_Info_Cannot_Invent_Chat_Action()
    {
        Assert.False((await _r.EvaluateAsync(C.Http(1,C.Source(),host:"slack.com",uri:"/api/users.info",bytes:200000,info:"files.upload sendDocument"))).Matched);
    }
    [Fact] public async Task Bot_Token_Redacted_And_Sni_Conflict_Rejected()
    {
        var s=C.Source();var c=C.Http(1,s,host:"api.telegram.org",uri:"/botprivate110/sendDocument",bytes:250000);var r=await _r.EvaluateAsync(c);Assert.True(r.Matched);var e=Assert.Single(r.Events);Assert.DoesNotContain("private110",e.Description);Assert.DoesNotContain("private110",e.Evidence);Assert.DoesNotContain(e.StructuredEvidence!.Items,x=>x.Key=="http.uri");var bad=C.Http(2,s,host:"api.telegram.org",uri:"/botprivate110/sendDocument",bytes:250000);bad.Record.Sni="other.example";Assert.False((await _r.EvaluateAsync(bad)).Matched);
    }
}
