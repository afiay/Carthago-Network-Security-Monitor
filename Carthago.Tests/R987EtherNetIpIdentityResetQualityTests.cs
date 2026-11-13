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
public sealed class R987EtherNetIpIdentityResetQualityTests
{
    private static readonly DateTime Epoch=new(2026,11,13,0,0,0,DateTimeKind.Utc);
    private static void U16(byte[] p,int at,ushort v)=>BinaryPrimitives.WriteUInt16LittleEndian(p.AsSpan(at,2),v);
    private static void U32(byte[] p,int at,uint v)=>BinaryPrimitives.WriteUInt32LittleEndian(p.AsSpan(at,4),v);
    private static void U64(byte[] p,int at,ulong v)=>BinaryPrimitives.WriteUInt64LittleEndian(p.AsSpan(at,8),v);
    private static byte[] Request(ulong context=0x123456789ABCDEF0UL)
    {
        var p=new byte[28];U16(p,0,0x65);U16(p,2,4);U64(p,12,context);U16(p,24,1);return p;
    }
    private static byte[] Response(uint handle=1,ulong context=0x123456789ABCDEF0UL)
    {
        var p=Request(context);U32(p,4,handle);return p;
    }
    private static TrafficRecord Parse(PacketHandler h,byte[] data,bool client=true,uint seq=101,
        uint ack=201,byte flags=0x18,int port=51000,string src="8.8.8.8",string dst="10.1.2.45",int service=44818)
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
    private static void Syn(PacketHandler h,int port=51000,string src="8.8.8.8",string dst="10.1.2.45",int service=44818)
    {
        Parse(h,Array.Empty<byte>(),seq:100,ack:0,flags:2,port:port,src:src,dst:dst,service:service);
        Parse(h,Array.Empty<byte>(),false,200,101,0x12,port,src,dst,service);
    }
    private static TrafficRecord Capture(PacketHandler h,byte[]? request=null,byte[]? response=null,
        string src="8.8.8.8",string dst="10.1.2.45",int service=44818)
    {
        var p=request??Request();Syn(h,src:src,dst:dst,service:service);
        Parse(h,p,src:src,dst:dst,service:service);
        return Parse(h,response??Response(),false,201,101+(uint)p.Length,src:src,dst:dst,service:service);
    }
    private static RuleEvaluationContext At(TrafficRecord r,int s)=>new(r,Sensitivity.Balanced,Epoch.AddSeconds(s));


    private static byte[] Reset(uint handle=1,ushort timeout=0)
    {
        var p=new byte[47];
        U16(p,0,0x6F);U16(p,2,23);U32(p,4,handle);
        U16(p,28,timeout);U16(p,30,2);U16(p,36,0xB2);U16(p,38,7);
        new byte[]{5,2,0x20,1,0x24,1,0}.CopyTo(p,40);return p;
    }
    private static TrafficRecord Exchange(PacketHandler h,byte[]? payload=null,uint handle=1,
        string src="8.8.8.8",string dst="10.1.2.45")
    {
        Capture(h,Request(),Response(handle),src,dst);
        return Parse(h,payload??Reset(handle),seq:129,ack:229,src:src,dst:dst);
    }
    [Theory]
    [InlineData(1u,0)]
    [InlineData(uint.MaxValue,30)]
    [InlineData(0x12345678u,1)]
    public async Task CompleteCaptureAndHandleBoundaries(uint handle,int timeout)
    {
        var r=Exchange(new PacketHandler(),Reset(handle,(ushort)timeout),handle);
        Assert.True(r.EtherNetIpIdentityResetObserved);
        Assert.Equal("enip.tcp.identity_reset.request",r.ApplicationProtocol);
        Assert.False(r.EtherNetIpRegisterSessionObserved);
        r.Info="PRIVATE-CIP-RESET-MARKER";
        var result=await new R987_PublicEtherNetIpIdentityResetRule().EvaluateAsync(At(r,0));
        Assert.True(result.Matched);
        Assert.DoesNotContain("PRIVATE-CIP-RESET-MARKER",JsonSerializer.Serialize(result.Events));
        Assert.False((await new R986_PrivateEtherNetIpRegisterSessionRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Theory]
    [InlineData("command")]
    [InlineData("length")]
    [InlineData("handle")]
    [InlineData("status")]
    [InlineData("options")]
    [InlineData("interface")]
    [InlineData("timeout")]
    [InlineData("item-count")]
    [InlineData("address-type")]
    [InlineData("address-length")]
    [InlineData("data-type")]
    [InlineData("data-length")]
    [InlineData("service")]
    [InlineData("path-size")]
    [InlineData("class-segment")]
    [InlineData("class")]
    [InlineData("instance-segment")]
    [InlineData("instance")]
    [InlineData("reset-type")]
    [InlineData("truncated")]
    [InlineData("coalesced")]
    public async Task OtherCipOperationsAndMalformedFramesFailClosed(string kind)
    {
        var p=Reset();
        switch(kind)
        {
            case "command":U16(p,0,0x70);break;
            case "length":U16(p,2,22);break;
            case "handle":U32(p,4,2);break;
            case "status":U32(p,8,1);break;
            case "options":U32(p,20,1);break;
            case "interface":U32(p,24,1);break;
            case "timeout":U16(p,28,31);break;
            case "item-count":U16(p,30,1);break;
            case "address-type":U16(p,32,0xA1);break;
            case "address-length":U16(p,34,1);break;
            case "data-type":U16(p,36,0xB1);break;
            case "data-length":U16(p,38,6);break;
            case "service":p[40]=0x0E;break;
            case "path-size":p[41]=1;break;
            case "class-segment":p[42]=0x21;break;
            case "class":p[43]=2;break;
            case "instance-segment":p[44]=0x25;break;
            case "instance":p[45]=2;break;
            case "reset-type":p[46]=1;break;
            case "truncated":p=p[..^1];break;
            case "coalesced":p=p.Concat(Reset()).ToArray();break;
        }
        var r=Exchange(new PacketHandler(),p);
        Assert.False(r.EtherNetIpIdentityResetObserved);
        Assert.False((await new R987_PublicEtherNetIpIdentityResetRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Theory]
    [InlineData("no-registration")]
    [InlineData("no-response")]
    [InlineData("wrong-synack")]
    [InlineData("wrong-context")]
    [InlineData("other-port")]
    [InlineData("wrong-ack")]
    [InlineData("gap")]
    [InlineData("replay-registration")]
    [InlineData("extra-client")]
    [InlineData("extra-server")]
    [InlineData("fin")]
    [InlineData("rst")]
    [InlineData("reuse")]
    [InlineData("expired")]
    [InlineData("reverse-time")]
    public async Task SessionAndResetControlsFailClosed(string kind)
    {
        DateTime now=Epoch;var h=new PacketHandler(()=>now);
        if(kind=="wrong-synack")
        {
            Parse(h,Array.Empty<byte>(),seq:100,ack:0,flags:2);
            Parse(h,Array.Empty<byte>(),false,200,100,0x12);
        }
        else Syn(h);
        if(kind!="no-registration")Parse(h,Request());
        if(kind!="no-registration"&&kind!="no-response")
            Parse(h,Response(context:kind=="wrong-context"?7UL:0x123456789ABCDEF0UL),false,201,129);
        if(kind=="replay-registration")Parse(h,Request());
        if(kind=="extra-client")Parse(h,new byte[]{1,2,3,4,5,6,7,8},seq:129,ack:229);
        if(kind=="extra-server")Parse(h,new byte[]{1,2,3,4,5,6,7,8},false,229,129);
        if(kind=="fin"||kind=="rst")Parse(h,Array.Empty<byte>(),seq:129,ack:229,flags:kind=="fin"?(byte)0x11:(byte)0x14);
        if(kind=="reuse")Syn(h);
        if(kind=="expired")now=now.AddSeconds(31);
        if(kind=="reverse-time")now=now.AddSeconds(-1);
        var r=Parse(h,Reset(),seq:kind=="gap"?130u:kind=="extra-client"?137u:129u,
            ack:kind=="wrong-ack"?228u:kind=="extra-server"?237u:229u,port:kind=="other-port"?51001:51000);
        Assert.False(r.EtherNetIpIdentityResetObserved);
        Assert.False((await new R987_PublicEtherNetIpIdentityResetRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task RegistrationIsNotResetAndThirtySecondBoundary()
    {
        DateTime now=Epoch;var h=new PacketHandler(()=>now);
        var registration=Capture(h);
        Assert.True(registration.EtherNetIpRegisterSessionObserved);
        Assert.False((await new R987_PublicEtherNetIpIdentityResetRule().EvaluateAsync(At(registration,0))).Matched);
        Assert.True((await new R986_PrivateEtherNetIpRegisterSessionRule().EvaluateAsync(At(registration,0))).Matched);
        now=now.AddSeconds(30);
        var r=Parse(h,Reset(),seq:129,ack:229);
        Assert.True(r.EtherNetIpIdentityResetObserved);
        Assert.False(Parse(h,Reset(),seq:176,ack:229).EtherNetIpIdentityResetObserved);
    }
    [Fact]
    public async Task ScopeForgeryAndContradictions()
    {
        var rule=new R987_PublicEtherNetIpIdentityResetRule();
        foreach(var r in new[]{Exchange(new PacketHandler(),src:"10.1.1.10"),
            Exchange(new PacketHandler(),dst:"9.9.9.9")})
            Assert.False((await rule.EvaluateAsync(At(r,0))).Matched);
        var fake=JsonSerializer.Deserialize<TrafficRecord>("{\"EtherNetIpIdentityResetObserved\":true}")!;
        Assert.False(fake.EtherNetIpIdentityResetObserved);
        var label=Parse(new PacketHandler(),Reset());label.ApplicationProtocol="enip.tcp.identity_reset.request";
        Assert.False((await rule.EvaluateAsync(At(label,0))).Matched);
        foreach(string kind in new[]{"id","udp","dns","tls","http","port","label","registration"})
        {
            var r=Exchange(new PacketHandler());
            switch(kind)
            {
                case "id":r.Id=Guid.Empty;break;
                case "udp":r.IsUdp=true;break;
                case "dns":r.DnsIsResponse=true;break;
                case "tls":r.Sni="other.example";break;
                case "http":r.HttpMethod="GET";break;
                case "port":r.DestinationPort=44819;break;
                case "label":r.ApplicationProtocol="TCP";break;
                case "registration":r.EtherNetIpRegisterSessionObserved=true;break;
            }
            Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
        }
    }
    [Fact]
    public async Task DuplicateReverseCooldownAndPeerIsolation()
    {
        var rule=new R987_PublicEtherNetIpIdentityResetRule();var first=Exchange(new PacketHandler());
        Assert.True((await rule.EvaluateAsync(At(first,100))).Matched);
        Assert.False((await rule.EvaluateAsync(At(first,101))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Exchange(new PacketHandler()),99))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Exchange(new PacketHandler()),200))).Suppressed);
        Assert.True((await rule.EvaluateAsync(At(Exchange(new PacketHandler(),src:"8.8.4.4"),201))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Exchange(new PacketHandler()),1000))).Matched);
        Assert.True((await new R987_PublicEtherNetIpIdentityResetRule().EvaluateAsync(At(first,100))).Matched);
    }
    [Fact]
    public void RegistryUniqueAndShadow()
    {
        var rules=RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count,rules.Select(r=>r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        var rule=Assert.IsType<R987_PublicEtherNetIpIdentityResetRule>(Assert.Single(rules.Where(r=>r.Descriptor.RuleId=="R987")));
        Assert.Equal(RulePrecisionMaturity.Candidate,rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow,rule.PrecisionProfile.DefaultMode);
    }
}
