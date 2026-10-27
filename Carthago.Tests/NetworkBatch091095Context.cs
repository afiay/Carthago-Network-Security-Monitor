// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;
internal static class NetworkBatch091095Context
{
    internal static readonly DateTime Origin=DateTime.UtcNow.AddMinutes(-10);

    internal static RuleEvaluationContext Http(int seconds,
        string uri="/",string? userAgent=null,string? info=null,
        string method="GET",string? headers=null)
    {
        var r=new TrafficRecord
        {
            Source="10.91.0.10",Destination="10.91.1.10",IpVersion=4,
            Protocol="TCP",IsTcp=true,TcpFlags=0x18,
            SourcePort=51000,DestinationPort=80,Length=256,
            HttpMethod=method,HttpHost="app.example.test",HttpUri=uri,
            HttpRequestHeaders=headers,HttpUserAgent=userAgent,Info=info,
            ApplicationProtocol="HTTP"
        };
        return new(r,Sensitivity.Balanced,Origin.AddSeconds(seconds));
    }

    internal static RuleEvaluationContext Dns(int seconds,string query,
        string? source="10.94.0.10",string destination="8.8.8.8",
        string? qtype="A",bool response=false,string protocol="DNS",
        string? app="DNS",string? info=null)
    {
        var r=new TrafficRecord
        {
            Source=source,Destination=destination,IpVersion=4,Protocol=protocol,
            IsUdp=true,SourcePort=53000,DestinationPort=53,
            ApplicationProtocol=app,ApplicationService="DNS",
            DnsQname=query,DnsQtype=qtype,DnsIsResponse=response,
            DnsRcode="NOERROR",Info=info
        };
        return new(r,Sensitivity.Balanced,Origin.AddSeconds(seconds));
    }
}
