// SPDX-License-Identifier: MIT
using System;
using System.Text;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;
namespace Carthago.Tests;
internal static class NetworkBatch156165Context
{
    internal static readonly DateTime Origin=new(2026,10,27,20,0,0,DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r,int seconds=0)
        =>new(r,Sensitivity.Balanced,Origin.AddSeconds(seconds));
    internal static TrafficRecord Http(string uri="/swagger.json",string method="GET")
        =>new()
        {
            Id=Guid.NewGuid(),Source="203.0.113.156",Destination="10.156.0.20",
            IpVersion=4,SourcePort=51000,DestinationPort=443,
            Protocol="HTTPS",ApplicationProtocol="HTTPS",ApplicationService="HTTPS",
            IsTcp=true,HttpHost="api.internal.local",HttpUri=uri,HttpMethod=method,
            HttpRequestHeaders="Host: api.internal.local",HttpUserAgent="curl/8.7",
            Length=2048,L4Len=2048
        };
    private static string Part(string value)=>Convert.ToBase64String(Encoding.UTF8.GetBytes(value))
        .TrimEnd('=').Replace('+','-').Replace('/','_');
    internal static string Jwt(bool none=true)
        =>Part(none?"{\"alg\":\"none\",\"typ\":\"JWT\"}":"{\"alg\":\"HS256\",\"typ\":\"JWT\"}")+"."+
          Part("{\"sub\":\"test-subject\",\"iat\":100}")+"."+(none?"":"ZmFrZXNpZ25hdHVyZQ");
}
