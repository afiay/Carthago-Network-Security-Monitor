// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; bounded instance-owned evidence windows only.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
 internal static class Research656Evidence
 {
   internal static bool HostIs(string? candidate,string root)
   {
     if(string.IsNullOrWhiteSpace(candidate) || candidate.Length>254)return false;
     var host=candidate.TrimEnd('.');
     return host.Equals(root,StringComparison.OrdinalIgnoreCase)
       ||host.EndsWith("."+root,StringComparison.OrdinalIgnoreCase);
   }
   internal static bool ValidProcess(TrafficRecord r,params string[] names)
   {
     if(r==null || r.ProcessId<=0 || r.ProcessName==null)return false;
     var p=NetworkBatch266270Evidence.Process(r);
     return p.Length>0 && names.Contains(p,StringComparer.Ordinal);
   }
   internal static bool PrivatePublic(TrafficRecord r,bool outbound)
     => Research646Evidence.Pair(r,!outbound,out _,out _);
   internal static bool NativeTcp(TrafficRecord r,bool outbound)
     => PrivatePublic(r,outbound)&&r.IsTcp&&!r.IsUdp&&!r.IsQuic
       &&string.Equals(r.Protocol,"TCP",StringComparison.OrdinalIgnoreCase)
       &&r.SourcePort is >0 and <=65535 &&r.DestinationPort is >0 and <=65535
       &&r.Length>=40 &&r.DnsQname==null;
 }
 internal sealed class Research656DistinctWindow
 {
   private sealed class Slot
   {
     internal DateTime First,Latest;
     internal readonly HashSet<Guid> Seen=new();
     internal readonly HashSet<string> Signals=new(StringComparer.Ordinal);
   }
   private readonly object _gate=new();
   private readonly Dictionary<string,Slot> _slots=new(StringComparer.Ordinal);
   internal bool Observe(string key,string signal,Guid id,DateTime at,int threshold=2)
   {
     if(string.IsNullOrWhiteSpace(key)||string.IsNullOrWhiteSpace(signal)||id==Guid.Empty
       ||at.Kind!=DateTimeKind.Utc ||threshold is <2 or >4)return false;
     lock(_gate)
     {
       if(!_slots.TryGetValue(key,out var slot))
       {
         if(_slots.Count>=512)
         {
           foreach(var k in _slots.Where(x=>at>=x.Value.Latest&&at-x.Value.Latest>TimeSpan.FromMinutes(10))
             .Select(x=>x.Key).ToArray())_slots.Remove(k);
           if(_slots.Count>=512)return false;
         }
         slot=new Slot{First=at};_slots.Add(key,slot);
       }
       if(at<=slot.Latest||slot.Seen.Contains(id))return false;
       if(at-slot.First>TimeSpan.FromMinutes(5))
       {
          slot.First=at;slot.Seen.Clear();slot.Signals.Clear();
       }
       if(slot.Seen.Count>=96)return false;
       slot.Seen.Add(id);slot.Last=at;slot.Signals.Add(signal);
       if(slot.Signals.Count<threshold)return false;
       slot.First=at;slot.Seen.Clear();slot.Signals.Clear();
       return true;
     }
   }
 }
 internal sealed class Research656UniformWindow
 {
   private sealed class Slot
   {
     internal DateTime Last,Start;
     internal int Length,Count;
     internal readonly HashSet<Guid> Ids=new();
   }
   private readonly object _gate=new();
   private readonly Dictionary<string,Slot> _slots=new(StringComparer.Ordinal);
   internal bool Observe(string key,Guid id,int length,DateTime at)
   {
     if(id==Guid.Empty||string.IsNullOrEmpty(key)||at.Kind!=DateTimeKind.Utc
       ||length is <700 or >1400)return false;
     lock(_gate)
     {
       if(!_slots.TryGetValue(key,out var slot))
       {
         if(_slots.Count>=512)
         {
            foreach(var k in _slots.Where(x=>at>=x.Value.Last&&at-x.Value.Last>TimeSpan.FromMinutes(10))
              .Select(x=>x.Key).ToArray())_slots.Remove(k);
            if(_slots.Count>=512)return false;
         }
         slot=new Slot{Start=at,Last=at,Length=length};_slots.Add(key,slot);
       }
       if(at<slot.Last||slot.Ids.Contains(id))return false;
       var delta=(at-slot.Last).TotalSeconds;
       var suitable=slot.Count==0||(delta>=9&&delta<=21&&at-slot.Start<=TimeSpan.FromSeconds(90)
          &&Math.Abs(length-slot.Length)<=16);
       if(!suitable){slot.Ids.Clear();slot.Count=0;slot.Length=length;slot.Start=at;}
       if(slot.Ids.Count>=8)return false;
       slot.Ids.Add(id);slot.Count++;slot.Last=at;
       if(slot.Count<4)return false;
       slot.Count=0;slot.Ids.Clear();slot.Start=at;
       return true;
     }
   }
 }
 internal sealed class Research656WebdavThenSmb
 {
   private sealed class Slot{internal Guid Id;internal DateTime At;}
   private readonly Dictionary<string,Slot> _starts=new(StringComparer.Ordinal);
   private readonly object _gate=new();
   internal bool Observe(string key,Guid id,DateTime at,bool first)
   {
      if(string.IsNullOrEmpty(key)||id==Guid.Empty||at.Kind!=DateTimeKind.Utc)return false;
      lock(_gate)
      {
         if(first)
         {
            if(_starts.Count>=512)
            {
               foreach(var k in _starts.Where(x=>at>=x.Value.At&&at-x.Value.At>TimeSpan.FromMinutes(5))
                 .Select(x=>x.Key).ToArray())_starts.Remove(k);
               if(_starts.Count>=512)return false;
            }
            _starts[key]=new Slot{Id=id,At=at};return false;
         }
         if(!_starts.TryGetValue(key,out var begin)||begin.Id==id||at<=begin.At
           ||at-begin.At>TimeSpan.FromMinutes(3))return false;
         _starts.Remove(key);return true;
      }
   }
 }
}
