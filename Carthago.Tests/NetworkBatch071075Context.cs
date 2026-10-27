// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
namespace Carthago.Tests;
internal static class NetworkBatch071075Context
{
    internal static readonly DateTime T0=DateTime.UtcNow.AddMinutes(-10);
    internal static RuleEvaluationContext Tcp(int second,string source="10.71.0.10",
        string destination="10.71.1.1",int port=3389,ushort? flags=2,
        string protocol="TCP",string? app=null,string? info=null,int? version=4)
        => new(new TrafficRecord { IpVersion=version,Source=source,Destination=destination,
            Protocol=protocol,IsTcp=protocol=="TCP",IsUdp=protocol=="UDP",SourcePort=50000,
            DestinationPort=port,TcpFlags=flags,ApplicationProtocol=app,Info=info },
            Sensitivity.Balanced,T0.AddSeconds(second));
    internal static RuleEvaluationContext Ipv6(int second,string source="fd71::10",
        string destination="2001:4860::8888",string network="IPv4Only")
        => new(new TrafficRecord { IpVersion=6,Source=source,Destination=destination,
            NetworkType=network,Protocol="TCP",IsTcp=true,SourcePort=50000,DestinationPort=443 },
            Sensitivity.Balanced,T0.AddSeconds(second));
    internal static RuleEvaluationContext Multicast(int second,string source="fe80::71",
        string destination="ff02::fb",int port=5353,string protocol="UDP",string? info=null)
        => new(new TrafficRecord { IpVersion=6,Source=source,Destination=destination,
            Protocol=protocol,IsUdp=protocol=="UDP",IsTcp=protocol=="TCP",
            SourcePort=port,DestinationPort=port,Info=info },
            Sensitivity.Balanced,T0.AddSeconds(second));
}
