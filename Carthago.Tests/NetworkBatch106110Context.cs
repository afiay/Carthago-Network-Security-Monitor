// SPDX-License-Identifier: MIT
using Carthago.Engine.Rules;
namespace Carthago.Tests;
internal static class NetworkBatch106110Context
{
    internal static string Source()=>NetworkBatch101105Context.Source();
    internal static RuleEvaluationContext Http(int t,string src,string host="mega.nz",string method="POST",int bytes=1200000,string uri="/upload",string process="curl.exe",string? info=null)
        =>NetworkBatch101105Context.Cloud(t,src,host:host,method:method,bytes:bytes,uri:uri,process:process,info:info);
    internal static RuleEvaluationContext Sweep(int t,string src,int target)
    {
        var c=Http(t,src,bytes:128);
        c.Record.Destination="10.42.0."+target;
        c.Record.DestinationPort=445;
        c.Record.HttpHost=null;c.Record.HttpMethod=null;c.Record.HttpUri=null;
        c.Record.ApplicationProtocol="SMB";c.Record.ApplicationService="SMB";
        return c;
    }
    internal static RuleEvaluationContext Inbound(int t,string src)
    {
        var c=Http(t,src,method:"GET",bytes:13000000);
        c.Record.Source="198.51.100.10";c.Record.Destination=src;
        return c;
    }
}
