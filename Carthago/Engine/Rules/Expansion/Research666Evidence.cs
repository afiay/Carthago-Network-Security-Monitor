// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Validation and bounded instance-local windows only.
// No shared behavioral predicate and no rule convergence.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
 internal static class Research666Evidence
 {
   internal static bool Outbound(TrafficRecord r)
     => Research646Evidence.Pair(r,false,out _,out _);
   internal static bool Inbound(TrafficRecord r)
     => Research646Evidence.Pair(r,true,out _,out _);
   internal static bool Tcp(TrafficRecord r)
     => r!=null&&r.Id!=Guid.Empty&&r.IpVersion==4&&r.IsTcp&&!r.IsUdp&&!r.IsQuic
        &&string.Equals(r.Protocol,"TCP",StringComparison.OrdinalIgnoreCase)
        &&r.SourcePort is >0 and <=65535&&r.DestinationPort is >0 and <=65535
        &&r.Length>=40;
   internal static bool Process(TrafficRecord r,params string[] names)
   {
     if(r==null||r.ProcessId<=0)return false;
     var name=NetworkBatch266270Evidence.Process(r);
     return name.Length>0&&names.Contains(name,StringComparer.Ordinal);
   }
   internal static bool DnsRoot(string? host,string domain)
   {
     if(string.IsNullOrWhiteSpace(host)||host.Length>253)return false;
     host=host.TrimEnd('.');
     return host.Equals(domain,StringComparison.OrdinalIgnoreCase)
       ||host.EndsWith("."+domain,StringComparison.OrdinalIgnoreCase);
   }
 }
 internal sealed class Research666TimedWindow
 {
   private sealed class Slot
   {
      internal DateTime First,Last;
      internal int Length,Count;
      internal long Bytes;
      internal readonly HashSet<Guid> Ids=new();
   }
   private readonly object _gate=new();
   private readonly Dictionary<string,Slot> _slots=new(StringComparer.Ordinal);
   internal bool Observe(string key,Guid id,int size,DateTime at,int threshold,bool interval,int requiredBytes=0)
   {
     if(string.IsNullOrWhiteSpace(key)||id==Guid.Empty||at.Kind!=DateTimeKind.Utc
       ||size is <1 or >8192||threshold is <3 or >10)return false;
     lock(_gate)
     {
       if(!_slots.TryGetValue(key,out var slot))
       {
         if(_slots.Count>=512)
         {
            foreach(var stale in _slots.Where(x=>at>=x.Value.Last && at-x.Value.Last>TimeSpan.FromMinutes(5))
              .Select(x=>x.Key).ToArray())_slots.Remove(stale);
            if(_slots.Count>=512)return false;
         }
         slot=new Slot{First=at,Last=at,Length=size};_slots.Add(key,slot);
       }
       if(at<slot.Last||slot.Ids.Contains(id))return false;
       var delta=(at-slot.Last).TotalSeconds;
       if(at-slot.First>TimeSpan.FromMinutes(2)
         ||(interval&&slot.Count>0&&(delta<9||delta>31||Math.Abs(slot.Length-size)>4)))
       {slot.Ids.Clear();slot.Count=0;slot.Bytes=0;slot.First=at;slot.Length=size;}
       if(slot.Ids.Count>=32)return false;
       slot.Ids.Add(id);slot.Last=at;slot.Count++;slot.Bytes+=size;
       if(slot.Count<threshold||slot.Bytes<requiredBytes)return false;
       slot.Ids.Clear();slot.Count=0;slot.Bytes=0;slot.First=at;slot.Length=size;
       return true;
     }
   }
 }
 internal sealed class Research666BridgeWindow
 {
   private sealed class Start
   {
     internal Guid Id;
     internal DateTime At;
   }
   private readonly object _gate=new();
   private readonly Dictionary<string,Start> _pending=new(StringComparer.Ordinal);
   internal bool Observe(string key,Guid id,DateTime at,bool inbound)
   {
     if(id==Guid.Empty||string.IsNullOrEmpty(key)||at.Kind!=DateTimeKind.Utc)return false;
     lock(_gate)
     {
       if(inbound)
       {
         if(_pending.Count>=512)
         {
            foreach(var old in _pending.Where(x=>at>=x.Value.At&&at-x.Value.At>TimeSpan.FromMinutes(2))
              .Select(x=>x.Key).ToArray())_pending.Remove(old);
            if(_pending.Count>=512)return false;
         }
         if(_pending.TryGetValue(key,out var previous) && at<=previous.At)return false;
         _pending[key]=new Start{Id=id,At=at};return false;
       }
       if(!_pending.TryGetValue(key,out var start)||start.Id==id||at<=start.At
         ||at-start.At>TimeSpan.FromSeconds(40))return false;
       _pending.Remove(key);
       return true;
     }
   }
 }
}
