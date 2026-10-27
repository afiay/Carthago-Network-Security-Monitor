// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;
internal static class NetworkBatch101105Context
{
    internal static readonly DateTime Origin=DateTime.UtcNow.AddMinutes(-25);
    internal const string EncodedLabel="zx9q8v7m6n5p4t3k2rz0h1w2c3v4b5n6m7l8k9j0i1u2y3t4r5s6";
    internal static string Root()=>"batch"+Guid.NewGuid().ToString("N")[..10]+".example";
    internal static string Source()=>"10.104."+((int)Guid.NewGuid().ToByteArray()[0]%200+1)+"."+((int)Guid.NewGuid().ToByteArray()[1]%200+1);
    internal static RuleEvaluationContext Dns(int seconds,string name,string type="A",bool response=false,string? answers=null,string source="10.101.0.10")
    {
        var r=new TrafficRecord{
            Source=source,Destination="8.8.8.8",IpVersion=4,Protocol="DNS",
            ApplicationProtocol="DNS",ApplicationService="DNS",IsUdp=true,
            SourcePort=53000,DestinationPort=53,DnsQname=name,DnsQtype=type,
            DnsIsResponse=response,DnsAnswers=answers,DnsRcode="NOERROR",Length=128
        };
        return new(r,Sensitivity.Balanced,Origin.AddSeconds(seconds));
    }
    internal static RuleEvaluationContext Cloud(int seconds,string source,string host="dropbox.com",
        string method="POST",int bytes=700000,string uri="/upload",
        string process="powershell.exe",string? headers=null,string? info=null)
    {
        var r=new TrafficRecord{
            Source=source,Destination="198.51.100.10",IpVersion=4,Protocol="TCP",
            ApplicationProtocol="HTTP",ApplicationService="HTTPS",IsTcp=true,
            TcpFlags=0x18,SourcePort=50101,DestinationPort=443,Length=bytes,L4Len=bytes,
            HttpHost=host,HttpMethod=method,HttpUri=uri,ProcessName=process,
            HttpRequestHeaders=headers,Info=info
        };
        return new(r,Sensitivity.Balanced,Origin.AddSeconds(seconds));
    }
}
