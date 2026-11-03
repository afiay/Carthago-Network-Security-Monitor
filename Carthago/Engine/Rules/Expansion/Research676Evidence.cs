// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Bounded input hygiene and time state only; no rule convergence.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 internal static class Research676Evidence
 {
  internal static bool PrivatePair(TrafficRecord r,out IPAddress a,out IPAddress b)
  {
    a=IPAddress.None;b=IPAddress.None;
    if(r==null || r.Id==Guid.Empty || r.IpVersion!=4
      || !IPAddress.TryParse(r.Source,out var parsedA) || parsedA is null
      || !IPAddress.TryParse(r.Destination,out var parsedB) || parsedB is null)
      return false;

    a=parsedA;
    b=parsedB;
    return Research646Evidence.Private(a) && Research646Evidence.Private(b);
  }
  internal static bool PublicToPrivate(TrafficRecord r)
    => Research646Evidence.Pair(r,true,out _,out _);
  internal static bool PrivateToPublic(TrafficRecord r)
    => Research646Evidence.Pair(r,false,out _,out _);
  internal static bool Tcp(TrafficRecord r)
    => r!=null && r.Id!=Guid.Empty && r.IpVersion==4 && r.IsTcp && !r.IsUdp && !r.IsQuic
      && string.Equals(r.Protocol,"TCP",StringComparison.OrdinalIgnoreCase)
      && r.SourcePort is >0 and <=65535 && r.DestinationPort is >0 and <=65535
      && r.Length>=40;
  internal static bool Syn(TrafficRecord r)
    => Tcp(r)&&r.TcpFlags==0x02&&r.L4Len is null or 0
      &&r.HttpMethod==null&&r.DnsQname==null&&r.TlsVersion==null
      &&r.ApplicationProtocol==null;
  internal static bool SynAck(TrafficRecord r)
    => Tcp(r)&&r.TcpFlags==0x12&&r.L4Len is null or 0
      &&r.HttpMethod==null&&r.DnsQname==null&&r.TlsVersion==null
      &&r.ApplicationProtocol==null;
  internal static string Prefix24(IPAddress ip)
  {
    var b=ip.GetAddressBytes();
    return b[0]+"."+b[1]+"."+b[2];
  }
  internal static bool Process(TrafficRecord r,params string[] allowed)
  {
    if(r==null||r.ProcessId<=0)return false;
    var actual=NetworkBatch266270Evidence.Process(r);
    return actual.Length>0&&allowed.Contains(actual,StringComparer.Ordinal);
  }
 }
 internal sealed class Research676OrderedWindow
 {
   private sealed class Slot
   {
     internal int Last,Count;
     internal DateTime First,Latest;
     internal readonly HashSet<Guid> Ids=new();
   }
   private readonly object _gate=new();
   private readonly Dictionary<string,Slot> _states=new(StringComparer.Ordinal);
   internal bool Observe(string key,int target,Guid id,DateTime at,int lengthSeconds)
   {
     if(string.IsNullOrWhiteSpace(key)||id==Guid.Empty||at.Kind!=DateTimeKind.Utc
       ||target is <0 or >255||lengthSeconds is <10 or >180)return false;
     lock(_gate)
     {
       if(!_states.TryGetValue(key,out var st))
       {
         if(_states.Count>=512)
         {
           foreach(var old in _states.Where(x=>at>=x.Value.Latest&&at-x.Value.Latest>TimeSpan.FromMinutes(5))
              .Select(x=>x.Key).ToArray())_states.Remove(old);
           if(_states.Count>=512)return false;
         }
         st=new Slot{First=at,Latest=DateTime.MinValue,Last=-1};_states.Add(key,st);
       }
       if(at<=st.Latest||st.Ids.Contains(id))return false;
       if(at-st.First>TimeSpan.FromSeconds(lengthSeconds)||st.Count>0&&target!=st.Last+1)
       {
         st.Count=0;st.Ids.Clear();st.First=at;
       }
       if(st.Ids.Count>=16)return false;
       st.Ids.Add(id);st.Count++;st.Last=target;st.Latest=at;
       if(st.Count<3)return false;
       st.Count=0;st.Ids.Clear();st.First=at;
       return true;
     }
   }
 }
 internal sealed class Research676KnockWindow
 {
   private sealed class Slot { internal int Stage;internal Guid Id;internal DateTime First,Last;}
   private readonly object _gate=new();
   private readonly Dictionary<string,Slot> _slots=new(StringComparer.Ordinal);
   internal bool Observe(string key,int stage,Guid id,DateTime at)
   {
     if(string.IsNullOrEmpty(key)||id==Guid.Empty||at.Kind!=DateTimeKind.Utc||stage is <0 or >2)return false;
     lock(_gate)
     {
       if(!_slots.TryGetValue(key,out var slot))
       {
         if(_slots.Count>=512)
         {
           foreach(var old in _slots.Where(x=>at>=x.Value.Last&&at-x.Value.Last>TimeSpan.FromMinutes(2))
               .Select(x=>x.Key).ToArray())_slots.Remove(old);
           if(_slots.Count>=512)return false;
         }
         slot=new Slot{Stage=-1,First=at,Last=DateTime.MinValue};_slots.Add(key,slot);
       }
       if(at<=slot.Last||slot.Id==id)return false;
       if(stage!=slot.Stage+1||at-slot.First>TimeSpan.FromSeconds(60))
       {
         if(stage!=0){slot.Stage=-1;slot.Last=at;return false;}
         slot.Stage=0;slot.First=at;slot.Last=at;slot.Id=id;return false;
       }
       slot.Stage=stage;slot.Id=id;slot.Last=at;
       if(stage!=2)return false;
       slot.Stage=-1;slot.First=at;
       return true;
     }
   }
 }
 internal sealed class Research676TcpSynPair
 {
   private sealed class Start{internal Guid Id;internal DateTime Time;}
   private readonly object _gate=new();
   private readonly Dictionary<string,Start> _pending=new(StringComparer.Ordinal);
   internal bool Observe(string key,Guid id,DateTime at,bool request)
   {
     if(string.IsNullOrEmpty(key)||id==Guid.Empty||at.Kind!=DateTimeKind.Utc)return false;
     lock(_gate)
     {
       if(request)
       {
         if(_pending.Count>=512)
         {
           foreach(var stale in _pending.Where(x=>at>=x.Value.Time&&at-x.Value.Time>TimeSpan.FromMinutes(2))
             .Select(x=>x.Key).ToArray())_pending.Remove(stale);
           if(_pending.Count>=512)return false;
         }
         if(_pending.TryGetValue(key,out var prev)&&at<=prev.Time)return false;
         _pending[key]=new Start{Id=id,Time=at};return false;
       }
       if(!_pending.TryGetValue(key,out var start)||start.Id==id
         ||at<=start.Time||at-start.Time>TimeSpan.FromSeconds(30))return false;
       _pending.Remove(key);return true;
     }
   }
 }
 
 internal sealed class Research676CadenceWindow
 {
   private sealed class Slot
   {
      internal DateTime First,Last;
      internal int Count,Length;
      internal readonly HashSet<Guid> Ids=new();
   }
   private readonly object _gate=new();
   private readonly Dictionary<string,Slot> _slots=new(StringComparer.Ordinal);
   internal bool Observe(string key,Guid id,int length,DateTime at,int threshold,bool interval)
   {
     if(string.IsNullOrWhiteSpace(key)||id==Guid.Empty||at.Kind!=DateTimeKind.Utc
       ||length is <100 or >1000||threshold!=3||!interval)return false;
     lock(_gate)
     {
       if(!_slots.TryGetValue(key,out var slot))
       {
         if(_slots.Count>=512)
         {
           foreach(var old in _slots.Where(x=>at>=x.Value.Last&&at-x.Value.Last>TimeSpan.FromMinutes(5))
              .Select(x=>x.Key).ToArray())_slots.Remove(old);
           if(_slots.Count>=512)return false;
         }
         slot=new Slot{First=at,Last=DateTime.MinValue,Length=length};
         _slots.Add(key,slot);
       }
       if(at<=slot.Last||slot.Ids.Contains(id))return false;
       if(slot.Count>0 && ((at-slot.Last).TotalSeconds<9||(at-slot.Last).TotalSeconds>31
          ||Math.Abs(length-slot.Length)>100||at-slot.First>TimeSpan.FromMinutes(2)))
       {slot.Count=0;slot.Ids.Clear();slot.First=at;slot.Length=length;}
       if(slot.Ids.Count>=8)return false;
       slot.Ids.Add(id);slot.Last=at;slot.Count++;
       if(slot.Count<3)return false;
       slot.Count=0;slot.Ids.Clear();slot.First=at;
       return true;
     }
   }
 }

}
