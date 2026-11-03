// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Shared evidence hygiene, not predicate convergence.
using System;
using System.Net;
using System.Linq;
using System.Net.Sockets;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 internal static class DnsSignatureRequestEvidence
 {
  internal static bool TryGetQuery(TrafficRecord r,out string name)
  {
   name=string.Empty;
   if(r==null||r.Id==Guid.Empty||r.DnsIsResponse||r.IsQuic
      ||!string.Equals(r.ApplicationService,"DNS",StringComparison.OrdinalIgnoreCase)
      ||r.DestinationPort!=53||r.SourcePort is null or <=0 or >65535
      ||r.L4Len is null or <12 or >4096||r.Length<40
      ||r.DnsQname==null||r.DnsQtype==null||r.HttpUri!=null||r.HttpMethod!=null
      ||r.TlsVersion!=null||r.Sni!=null||r.RedisRespConfigSetRequestObserved
      ||r.RedisRespConfigSetReplyOkObserved||r.RedisRespConfigSetReplyErrorObserved)return false;
   if(r.IsUdp)
   {
     if(r.IsTcp||!string.Equals(r.Protocol,"UDP",StringComparison.OrdinalIgnoreCase)
       ||r.ApplicationProtocol is not null and not "DNS")return false;
   }
   else if(!r.IsTcp||!string.Equals(r.Protocol,"TCP",StringComparison.OrdinalIgnoreCase)
       ||!string.Equals(r.ApplicationProtocol,"DNS",StringComparison.OrdinalIgnoreCase))return false;
   if(!IPAddress.TryParse(r.Source,out var source)||!IPAddress.TryParse(r.Destination,out var destination)
      ||source.AddressFamily!=destination.AddressFamily
      ||source.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))return false;
   var q=r.DnsQname.TrimEnd('.');
   if(q.Length<4||q.Length>253||q.IndexOf('.')<1)return false;
   var len=0;
   foreach(var c in q)
   {
    if(c=='.'){if(len is <1 or >63)return false;len=0;}
    else {if(!(c is >= 'a' and <= 'z'||c is >= 'A' and <= 'Z'||c is >= '0' and <= '9'||c=='-'||c=='_'))return false;len++;}
   }
   if(len is <1 or >63)return false;
   name=q.ToLowerInvariant();return true;
  }
  internal static DetectionEvent RedactQuery(DetectionEvent evt,string query)
  {
   if(evt==null||string.IsNullOrWhiteSpace(query))return evt;
   static string? Redact(string? value,string q)
    =>value?.Replace(q,"[REDACTED]",StringComparison.OrdinalIgnoreCase);
   evt.DestinationHost=Redact(evt.DestinationHost,query);
   evt.Description=Redact(evt.Description,query)??string.Empty;
   evt.Evidence=Redact(evt.Evidence,query);
   if(evt.StructuredEvidence is { } structured)
   {
    var items=structured.Items
      .Select(item=>item with { Value=Redact(item.Value,query)??string.Empty })
      .ToArray();
    evt.StructuredEvidence=new DetectionEvidenceSet(
      items,Redact(structured.Summary,query)??string.Empty);
   }
   return evt;
  }
 }
}
