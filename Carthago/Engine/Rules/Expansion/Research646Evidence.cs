// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Typed evidence hygiene and bounded windows, never merged predicates.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 internal static class Research646Evidence
 {
   internal static bool Private(IPAddress ip)
   {
     if(ip.AddressFamily!=AddressFamily.InterNetwork)return false;
     var b=ip.GetAddressBytes();
     return b[0]==10 || b[0]==172 && b[1] is >=16 and <=31 || b[0]==192 && b[1]==168;
   }
   internal static bool Public(IPAddress ip)
   {
     if(ip.AddressFamily!=AddressFamily.InterNetwork)return false;
     var b=ip.GetAddressBytes();
     return b[0]>0 && b[0]<224 && b[0]!=10 && b[0]!=127
       && !(b[0]==100 && b[1] is >=64 and <=127)
       && !(b[0]==169 && b[1]==254)
       && !(b[0]==172 && b[1] is >=16 and <=31)
       && !(b[0]==192 && (b[1]==168 || b[1]==0 || b[1]==88 && b[2]==99))
       && !(b[0]==198 && (b[1] is 18 or 19 || b[1]==51 && b[2]==100))
       && !(b[0]==203 && b[1]==0 && b[2]==113);
   }
   internal static bool Pair(TrafficRecord r,bool publicToPrivate,out IPAddress src,out IPAddress dst)
   {
      src=IPAddress.None;dst=IPAddress.None;
      if(r==null || r.Id==Guid.Empty || r.IpVersion!=4
        || !IPAddress.TryParse(r.Source,out var parsedSrc) || parsedSrc is null
        || !IPAddress.TryParse(r.Destination,out var parsedDst) || parsedDst is null
        || parsedSrc.AddressFamily!=AddressFamily.InterNetwork
        || parsedDst.AddressFamily!=AddressFamily.InterNetwork)
        return false;

      src=parsedSrc;
      dst=parsedDst;
      return publicToPrivate
        ? Public(src)&&Private(dst)
        : Private(src)&&Public(dst);
   }
   internal static bool Tcp(TrafficRecord r,bool publicToPrivate,bool payloadRequired=true)
   {
      return Pair(r,publicToPrivate,out _,out _) && r.IsTcp && !r.IsUdp && !r.IsQuic
        && string.Equals(r.Protocol,"TCP",StringComparison.OrdinalIgnoreCase)
        && r.SourcePort is >0 and <=65535 && r.DestinationPort is >0 and <=65535
        && r.Length>=40 && (!payloadRequired || r.L4Len is >=12 and <=4096)
        && r.HttpMethod==null && r.DnsQname==null && r.TlsVersion==null
        && !r.RedisRespConfigSetRequestObserved && !r.LdapCleartextSimpleBindObserved;
   }
   internal static bool SynAck(TrafficRecord r,int sourcePort)
     => Tcp(r,false,false) && r.SourcePort==sourcePort && r.TcpFlags==0x12
       && r.DestinationPort!=sourcePort && r.L4Len is null or 0
       && r.ApplicationProtocol==null;
   internal static string Subnet24(IPAddress address)
   {
     var b=address.GetAddressBytes();
     return b[0]+"."+b[1]+"."+b[2];
   }
 }
 internal sealed class Research646DistinctWindow
 {
    private const int MaxKeys=512,MaxPackets=96;
    private static readonly TimeSpan Window=TimeSpan.FromMinutes(5);
    private sealed class Slot
    {
      internal DateTime First,Latest;
      internal readonly HashSet<Guid> Ids=new();
      internal readonly HashSet<string> Targets=new(StringComparer.Ordinal);
    }
    private readonly object _gate=new();
    private readonly Dictionary<string,Slot> _slots=new(StringComparer.Ordinal);
    internal bool Observe(string key,string distinct,Guid id,DateTime at)
    {
      if(string.IsNullOrEmpty(key)||string.IsNullOrEmpty(distinct)||id==Guid.Empty||at.Kind!=DateTimeKind.Utc)return false;
      lock(_gate)
      {
        if(!_slots.TryGetValue(key,out var slot))
        {
          if(_slots.Count>=MaxKeys)
          {
            foreach(var stale in _slots.Where(k=>at>=k.Value.Latest && at-k.Value.Latest>Window).Select(k=>k.Key).ToArray())
              _slots.Remove(stale);
            if(_slots.Count>=MaxKeys)return false;
          }
          slot=new Slot{First=at};_slots.Add(key,slot);
        }
        if(at<=slot.Latest || slot.Ids.Contains(id))return false;
        if(at-slot.First>Window)
        {
          slot.First=at;slot.Ids.Clear();slot.Targets.Clear();
        }
        if(slot.Ids.Count>=MaxPackets)return false;
        slot.Ids.Add(id);slot.Latest=at;slot.Targets.Add(distinct);
        if(slot.Targets.Count<3)return false;
        slot.Ids.Clear();slot.Targets.Clear();slot.First=at;
        return true;
      }
    }
 }
}
