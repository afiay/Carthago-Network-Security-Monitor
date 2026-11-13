// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.ProtocolIntelligence;
using PacketDotNet;
using Xunit;

namespace Carthago.Tests;
public sealed class R970Iec104StartupOffQualityTests
{
    private static readonly DateTime Epoch=new(2026,11,13,0,0,0,DateTimeKind.Utc);
    private static byte[] Start(byte control=7)=>new byte[]{0x68,4,control,0,0,0};
    private static byte[] Off()=>new byte[]{0x68,14,0,0,0,0,46,1,6,0,1,0,1,0,0,1};
    private static TrafficRecord Parse(PacketHandler h,byte[] data,bool client=true,
        uint seq=107,uint ack=207,byte flags=0x18,int port=51000,
        string src="8.8.8.8",string dst="10.1.2.45",int service=2404)
    {
        var p=new byte[40+data.Length];p[0]=0x45;p[8]=64;p[9]=6;
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2,2),(ushort)p.Length);
        IPAddress.Parse(client?src:dst).GetAddressBytes().CopyTo(p,12);
        IPAddress.Parse(client?dst:src).GetAddressBytes().CopyTo(p,16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(20,2),(ushort)(client?port:service));
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(22,2),(ushort)(client?service:port));
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(24,4),seq);
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(28,4),ack);
        p[32]=0x50;p[33]=flags;data.CopyTo(p,40);
        return Assert.IsType<TrafficRecord>(h.ParseFrame(p,(LinkLayers)12));
    }
    private static void Syn(PacketHandler h,int port=51000,string src="8.8.8.8",
        string dst="10.1.2.45",int service=2404)
    {
        Parse(h,Array.Empty<byte>(),seq:100,ack:0,flags:2,port:port,src:src,dst:dst,service:service);
        Parse(h,Array.Empty<byte>(),false,200,101,0x12,port,src,dst,service);
    }
    private static TrafficRecord Capture(PacketHandler h,byte[]? command=null,string src="8.8.8.8",
        string dst="10.1.2.45",int port=51000,int service=2404)
    {
        Syn(h,port,src,dst,service);
        Parse(h,Start(),seq:101,ack:201,port:port,src:src,dst:dst,service:service);
        Parse(h,Start(0x0B),false,201,107,port:port,src:src,dst:dst,service:service);
        return Parse(h,command??Off(),port:port,src:src,dst:dst,service:service);
    }
    private static RuleEvaluationContext At(TrafficRecord r,int seconds)=>new(r,Sensitivity.Balanced,Epoch.AddSeconds(seconds));

    [Fact]
    public async Task RealFramesRequireFullSequenceAndDoNotLeak()
    {
        var r=Capture(new PacketHandler());
        Assert.True(r.Iec104StartupOffExecuteObserved);
        r.Info="PRIVATE-IEC104-COMMAND-MARKER";
        var result=await new R970_PublicIec104StartupOffExecuteRule().EvaluateAsync(At(r,0));
        Assert.True(result.Matched);
        Assert.DoesNotContain("PRIVATE-IEC104-COMMAND-MARKER",JsonSerializer.Serialize(result.Events));
    }
    [Theory]
    [InlineData("on")]
    [InlineData("select")]
    [InlineData("qualifier")]
    [InlineData("single")]
    [InlineData("interrogation")]
    [InlineData("test")]
    [InlineData("negative")]
    [InlineData("confirm")]
    [InlineData("originator")]
    [InlineData("zero-station")]
    [InlineData("broadcast-station")]
    [InlineData("zero-ioa")]
    [InlineData("sequence")]
    [InlineData("multiple")]
    [InlineData("send-counter")]
    [InlineData("receive-counter")]
    [InlineData("bad-length")]
    [InlineData("truncated")]
    [InlineData("coalesced")]
    public async Task ExactCommandAndFramingRequired(string kind)
    {
        var p=Off();
        switch(kind)
        {
            case "on":p[15]=2;break;
            case "select":p[15]=0x81;break;
            case "qualifier":p[15]=5;break;
            case "single":p[6]=45;break;
            case "interrogation":p[6]=100;break;
            case "test":p[8]=0x86;break;
            case "negative":p[8]=0x46;break;
            case "confirm":p[8]=7;break;
            case "originator":p[9]=1;break;
            case "zero-station":p[10]=0;break;
            case "broadcast-station":p[10]=p[11]=255;break;
            case "zero-ioa":p[12]=0;break;
            case "sequence":p[7]=0x81;break;
            case "multiple":p[7]=2;break;
            case "send-counter":p[2]=2;break;
            case "receive-counter":p[4]=2;break;
            case "bad-length":p[1]=13;break;
            case "truncated":p=p[..^1];break;
            case "coalesced":p=p.Concat(Off()).ToArray();break;
        }
        Assert.False(Iec104StartupOffSequence.IsOffExecute(p));
        var r=Capture(new PacketHandler(),p);
        Assert.False(r.Iec104StartupOffExecuteObserved);
        Assert.False((await new R970_PublicIec104StartupOffExecuteRule().EvaluateAsync(At(r,0))).Matched);
    }

    [Theory]
    [InlineData("no-syn")]
    [InlineData("no-synack")]
    [InlineData("no-start")]
    [InlineData("no-confirm")]
    [InlineData("wrong-confirm")]
    [InlineData("other-port")]
    [InlineData("wrong-ack")]
    [InlineData("gap")]
    [InlineData("retransmit")]
    [InlineData("fin")]
    [InlineData("reuse")]
    [InlineData("expiry")]
    public async Task SessionCorrelationFailsClosed(string kind)
    {
        DateTime now=Epoch;
        var h=new PacketHandler(()=>now);
        if(kind=="no-synack")
            Parse(h,Array.Empty<byte>(),seq:100,ack:0,flags:2);
        else if(kind!="no-syn") Syn(h);
        if(kind!="no-start") Parse(h,Start(),seq:101,ack:201);
        if(kind!="no-confirm")
            Parse(h,Start(kind=="wrong-confirm"?(byte)0x07:(byte)0x0B),false,201,107,
                port:kind=="other-port"?51001:51000);
        if(kind=="retransmit") Parse(h,Start(),seq:101,ack:201);
        if(kind=="fin") Parse(h,Array.Empty<byte>(),seq:107,ack:207,flags:0x11);
        if(kind=="reuse") Syn(h);
        if(kind=="expiry") now=now.AddSeconds(31);
        var r=Parse(h,Off(),seq:kind=="gap"?108u:107u,ack:kind=="wrong-ack"?206u:207u);
        Assert.False(r.Iec104StartupOffExecuteObserved);
        Assert.False((await new R970_PublicIec104StartupOffExecuteRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task ExactThirtySecondBoundaryAndOneShot()
    {
        DateTime now=Epoch;var h=new PacketHandler(()=>now);Syn(h);
        Parse(h,Start(),seq:101,ack:201);
        Parse(h,Start(0x0B),false,201,107);
        now=now.AddSeconds(30);
        Assert.True(Parse(h,Off()).Iec104StartupOffExecuteObserved);
        Assert.False(Parse(h,Off(),seq:123).Iec104StartupOffExecuteObserved);
        var rule=new R970_PublicIec104StartupOffExecuteRule();
        Assert.True((await rule.EvaluateAsync(At(Capture(new PacketHandler()),0))).Matched);
    }
    [Fact]
    public async Task ScopeForgeryAndContradictions()
    {
        var rule=new R970_PublicIec104StartupOffExecuteRule();
        foreach(var r in new[]{Capture(new PacketHandler(),src:"10.1.1.10"),
            Capture(new PacketHandler(),dst:"9.9.9.9"),Capture(new PacketHandler(),service:2405)})
            Assert.False((await rule.EvaluateAsync(At(r,0))).Matched);
        var fake=JsonSerializer.Deserialize<TrafficRecord>("{\"Iec104StartupOffExecuteObserved\":true}")!;
        Assert.False(fake.Iec104StartupOffExecuteObserved);
        var noProof=Parse(new PacketHandler(),Off());noProof.ApplicationProtocol="iec104";
        Assert.False((await rule.EvaluateAsync(At(noProof,0))).Matched);
        foreach(string kind in new[]{"id","tls","udp","dns","http","port"})
        {
            var r=Capture(new PacketHandler());
            switch(kind)
            {
                case "id":r.Id=Guid.Empty;break;
                case "tls":r.Sni="other.example";break;
                case "udp":r.IsUdp=true;break;
                case "dns":r.DnsIsResponse=true;break;
                case "http":r.HttpMethod="GET";break;
                case "port":r.DestinationPort=2405;break;
            }
            Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
        }
    }
    [Fact]
    public async Task CooldownDuplicateReverseAndPeerIsolation()
    {
        var rule=new R970_PublicIec104StartupOffExecuteRule();
        var first=Capture(new PacketHandler());
        Assert.True((await rule.EvaluateAsync(At(first,100))).Matched);
        Assert.False((await rule.EvaluateAsync(At(first,101))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Capture(new PacketHandler()),99))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(new PacketHandler()),200))).Suppressed);
        Assert.True((await rule.EvaluateAsync(At(Capture(new PacketHandler(),dst:"10.1.2.46"),201))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(new PacketHandler()),1000))).Matched);
        Assert.True((await new R970_PublicIec104StartupOffExecuteRule().EvaluateAsync(At(first,100))).Matched);
    }
    [Fact]
    public void RegistryUniqueAndShadow()
    {
        var rules=RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count,rules.Select(r=>r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        var rule=Assert.IsType<R970_PublicIec104StartupOffExecuteRule>(Assert.Single(rules.Where(r=>r.Descriptor.RuleId=="R970")));
        Assert.Equal(RulePrecisionMaturity.Candidate,rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow,rule.PrecisionProfile.DefaultMode);
    }
}
