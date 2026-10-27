// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules.CloudSaas;
using Xunit;
namespace Carthago.Tests;
public sealed class R109AdvancedAccuracyBatchTests
{
    private readonly R109_SuspiciousGitHubGitLabRawAccessRule _r=new();
    private static class C
    {
        internal static string Source()=>NetworkBatch106110Context.Source();
        internal static Carthago.Engine.Rules.RuleEvaluationContext Http(int t,string src,string host="mega.nz",string method="POST",int bytes=1200000,string uri="/upload",string process="curl.exe",string? info=null)=>NetworkBatch106110Context.Http(t,src,host,method,bytes,uri,process,info);
        internal static Carthago.Engine.Rules.RuleEvaluationContext Sweep(int t,string src,int dest)=>NetworkBatch106110Context.Sweep(t,src,dest);
        internal static Carthago.Engine.Rules.RuleEvaluationContext Inbound(int t,string src)=>NetworkBatch106110Context.Inbound(t,src);
    }
    [Fact] public async Task Parsed_Script_Fetch_Produces_Classification()
    {
        var r=await _r.EvaluateAsync(C.Http(1,C.Source(),host:"raw.githubusercontent.com",method:"GET",uri:"/owner/repo/install.ps1",bytes:500000,process:"powershell.exe"));Assert.True(r.Matched);Assert.Contains(Assert.Single(r.Events).StructuredEvidence!.Items,x=>x.Key=="host.classifier");
    }
    [Fact] public async Task Normal_Git_Blob_Is_Benign()
    {
        Assert.False((await _r.EvaluateAsync(C.Http(1,C.Source(),host:"github.com",method:"GET",uri:"/owner/repo/blob/main/install.ps1",bytes:500000))).Matched);
    }
    [Fact] public async Task Small_Readme_Fetch_Is_Benign()
    {
        Assert.False((await _r.EvaluateAsync(C.Http(1,C.Source(),host:"raw.githubusercontent.com",method:"GET",uri:"/owner/repo/README.md",bytes:2000,process:"chrome.exe"))).Matched);
    }
    [Fact] public async Task Packet_Info_Cannot_Invent_Payload_Path()
    {
        Assert.False((await _r.EvaluateAsync(C.Http(1,C.Source(),host:"raw.githubusercontent.com",method:"GET",uri:"/owner/repo/README.md",bytes:2000,process:"chrome.exe",info:"powershell install.ps1"))).Matched);
    }
    [Fact] public async Task Sensitive_Query_Redacted_And_Duplicate_Rejected()
    {
        var c=C.Http(1,C.Source(),host:"raw.githubusercontent.com",method:"GET",uri:"/owner/repo/install.ps1?token=private109",bytes:500000);var r=await _r.EvaluateAsync(c);Assert.True(r.Matched);var e=Assert.Single(r.Events);Assert.DoesNotContain("private109",e.Description);Assert.DoesNotContain("private109",e.Evidence);Assert.DoesNotContain(e.StructuredEvidence!.Items,x=>x.Key=="http.uri");Assert.False((await _r.EvaluateAsync(c)).Matched);
    }
}
