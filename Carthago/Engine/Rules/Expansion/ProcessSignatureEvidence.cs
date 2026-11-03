// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Process/tuple evidence hygiene; no merged predicates.
using System;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
  internal static class ProcessSignatureEvidence
  {
    internal static bool TryExternalTcp(TrafficRecord r,out string process)
    {
      process=string.Empty;
      return r!=null && NetworkBatch266270Evidence.ProcessEgress(r,out process)
        && process.Length>0;
    }
    internal static bool TryDnsOwner(TrafficRecord r,out string process)
    {
      process=string.Empty;
      if(r==null || r.ProcessId<=0 || r.IsTcp || !r.IsUdp || r.IsQuic
        || !string.Equals(r.Protocol,"UDP",StringComparison.OrdinalIgnoreCase)
        || r.DestinationPort!=53 || r.HttpMethod!=null || r.TlsVersion!=null)return false;
      process=NetworkBatch266270Evidence.Process(r);
      return process.Length>0;
    }
    internal static bool TryLoopbackRdp(TrafficRecord r,out string process)
    {
      process=string.Empty;
      if(r==null||r.Id==Guid.Empty||r.ProcessId<=0||r.SourcePort!=3389
        ||r.DestinationPort is null or <=0 or >65535
        ||!r.IsTcp||r.IsUdp||r.IsQuic||!string.Equals(r.Protocol,"TCP",StringComparison.OrdinalIgnoreCase)
        ||r.HttpMethod!=null||r.DnsQname!=null||r.TlsVersion!=null
        ||!IPAddress.TryParse(r.Source,out var src)||!IPAddress.TryParse(r.Destination,out var dst)
        ||src.AddressFamily!=dst.AddressFamily||!IPAddress.IsLoopback(src)||!IPAddress.IsLoopback(dst))
        return false;
      process=NetworkBatch266270Evidence.Process(r);
      return process.Length>0;
    }
    internal static bool EndsIn(string name,string domain)
      => name.Equals(domain,StringComparison.OrdinalIgnoreCase)
        ||name.EndsWith("."+domain,StringComparison.OrdinalIgnoreCase);
  }
}
