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
public sealed class R983FinsNodeNegotiationQualityTests
{
    private static readonly DateTime Epoch=new(2026,11,13,0,0,0,DateTimeKind.Utc);
    private static void U32(byte[] p,int at,uint v)=>BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(at,4),v);
    private static byte[] Request(uint node=0)
    {
        var p=new byte[20];"FINS"u8.CopyTo(p);U32(p,4,12);U32(p,16,node);return p;
    }
    private static byte[] Response(uint client=7,uint server=1)
    {
        var p=new byte[24];"FINS"u8.CopyTo(p);U32(p,4,16);U32(p,8,1);
        U32(p,16,client);U32(p,20,server);return p;
    }
    private static TrafficRecord Parse(PacketHandler h,byte[] data,bool client=true,uint seq=101,
        uint ack=201,byte flags=0x18,int port=51000,string src="8.8.8.8",string dst="10.1.2.45",int service=9600)
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
    private static void Syn(PacketHandler h,int port=51000,string src="8.8.8.8",string dst="10.1.2.45",int service=9600)
    {
        Parse(h,Array.Empty<byte>(),seq:100,ack:0,flags:2,port:port,src:src,dst:dst,service:service);
        Parse(h,Array.Empty<byte>(),false,200,101,0x12,port,src,dst,service);
    }
    private static TrafficRecord Capture(PacketHandler h,byte[]? request=null,byte[]? response=null,
        string src="8.8.8.8",string dst="10.1.2.45",int service=9600)
    {
        var p=request??Request();Syn(h,src:src,dst:dst,service:service);
        Parse(h,p,src:src,dst:dst,service:service);
        return Parse(h,response??Response(),false,201,101+(uint)p.Length,src:src,dst:dst,service:service);
    }
    private static RuleEvaluationContext At(TrafficRecord r,int s)=>new(r,Sensitivity.Balanced,Epoch.AddSeconds(s));


    [Theory]
    [InlineData(0,7,1)]
    [InlineData(1,1,254)]
    [InlineData(254,254,1)]
    public async Task ValidCaptureAutomaticAndExplicitNodes(int requested,int client,int server)
    {
        var r=Capture(new PacketHandler(),Request((uint)requested),Response((uint)client,(uint)server));
        Assert.True(r.FinsNodeNegotiationObserved);
        Assert.Equal("fins.tcp.node_negotiation.response",r.ApplicationProtocol);
        r.Info="PRIVATE-FINS-FIXTURE";
        var result=await new R983_PrivateFinsNodeNegotiationToPublicClientRule().EvaluateAsync(At(r,0));
        Assert.True(result.Matched);
        Assert.DoesNotContain("PRIVATE-FINS-FIXTURE",JsonSerializer.Serialize(result.Events));
        Assert.False((await new R973_PrivateOpcUaHelloAckToPublicClientRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Theory]
    [InlineData("request-magic")]
    [InlineData("request-length")]
    [InlineData("request-command")]
    [InlineData("request-error")]
    [InlineData("request-node")]
    [InlineData("request-truncated")]
    [InlineData("request-coalesced")]
    [InlineData("response-magic")]
    [InlineData("response-length")]
    [InlineData("response-command")]
    [InlineData("response-error")]
    [InlineData("client-zero")]
    [InlineData("client-255")]
    [InlineData("server-zero")]
    [InlineData("server-255")]
    [InlineData("same-node")]
    [InlineData("explicit-mismatch")]
    [InlineData("response-truncated")]
    [InlineData("response-coalesced")]
    public async Task MalformedAndBenignFramesFailClosed(string kind)
    {
        var request=Request();var response=Response();
        switch(kind)
        {
            case "request-magic":request[0]=0;break;
            case "request-length":U32(request,4,11);break;
            case "request-command":U32(request,8,2);break;
            case "request-error":U32(request,12,1);break;
            case "request-node":U32(request,16,255);break;
            case "request-truncated":request=request[..^1];break;
            case "request-coalesced":request=request.Concat(Request()).ToArray();break;
            case "response-magic":response[0]=0;break;
            case "response-length":U32(response,4,15);break;
            case "response-command":U32(response,8,2);break;
            case "response-error":U32(response,12,1);break;
            case "client-zero":U32(response,16,0);break;
            case "client-255":U32(response,16,255);break;
            case "server-zero":U32(response,20,0);break;
            case "server-255":U32(response,20,255);break;
            case "same-node":U32(response,20,7);break;
            case "explicit-mismatch":request=Request(8);break;
            case "response-truncated":response=response[..^1];break;
            case "response-coalesced":response=response.Concat(Response()).ToArray();break;
        }
        var r=Capture(new PacketHandler(),request,response);
        Assert.False(r.FinsNodeNegotiationObserved);
        Assert.False((await new R983_PrivateFinsNodeNegotiationToPublicClientRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Theory]
    [InlineData("no-syn")]
    [InlineData("no-synack")]
    [InlineData("wrong-synack")]
    [InlineData("no-request")]
    [InlineData("other-port")]
    [InlineData("wrong-ack")]
    [InlineData("gap")]
    [InlineData("retransmit")]
    [InlineData("second-client-payload")]
    [InlineData("fin")]
    [InlineData("rst")]
    [InlineData("reuse")]
    [InlineData("expired")]
    [InlineData("reverse-time")]
    public async Task SessionMismatchAndResetFailClosed(string kind)
    {
        DateTime now=Epoch;var h=new PacketHandler(()=>now);
        if(kind=="no-synack"||kind=="wrong-synack")
        {
            Parse(h,Array.Empty<byte>(),seq:100,ack:0,flags:2);
            if(kind=="wrong-synack")Parse(h,Array.Empty<byte>(),false,200,100,0x12);
        }
        else if(kind!="no-syn")Syn(h);
        if(kind!="no-request")Parse(h,Request());
        if(kind=="retransmit")Parse(h,Request());
        if(kind=="second-client-payload")Parse(h,Request(),seq:121);
        if(kind=="fin"||kind=="rst")Parse(h,Array.Empty<byte>(),seq:121,flags:kind=="fin"?(byte)0x11:(byte)0x14);
        if(kind=="reuse")Syn(h);
        if(kind=="expired")now=now.AddSeconds(31);
        if(kind=="reverse-time")now=now.AddSeconds(-1);
        var r=Parse(h,Response(),false,kind=="gap"?202u:201u,
            kind=="wrong-ack"?120u:121u,port:kind=="other-port"?51001:51000);
        Assert.False(r.FinsNodeNegotiationObserved);
        Assert.False((await new R983_PrivateFinsNodeNegotiationToPublicClientRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task ThirtySecondBoundaryAndOneShot()
    {
        DateTime now=Epoch;var h=new PacketHandler(()=>now);Syn(h);Parse(h,Request());
        now=now.AddSeconds(30);
        var first=Parse(h,Response(),false,201,121);
        Assert.True(first.FinsNodeNegotiationObserved);
        Assert.False(Parse(h,Response(),false,225,121).FinsNodeNegotiationObserved);
        Assert.True((await new R983_PrivateFinsNodeNegotiationToPublicClientRule().EvaluateAsync(At(first,0))).Matched);
    }
    [Fact]
    public async Task ScopeForgeryAndContradictions()
    {
        var rule=new R983_PrivateFinsNodeNegotiationToPublicClientRule();
        foreach(var r in new[]{Capture(new PacketHandler(),src:"10.1.1.10"),
            Capture(new PacketHandler(),dst:"9.9.9.9"),Capture(new PacketHandler(),service:9601)})
            Assert.False((await rule.EvaluateAsync(At(r,0))).Matched);
        var fake=JsonSerializer.Deserialize<TrafficRecord>("{\"FinsNodeNegotiationObserved\":true}")!;
        Assert.False(fake.FinsNodeNegotiationObserved);
        var label=Parse(new PacketHandler(),Response(),false);label.ApplicationProtocol="fins.tcp.node_negotiation.response";
        Assert.False((await rule.EvaluateAsync(At(label,0))).Matched);
        foreach(string kind in new[]{"id","tls","udp","dns","http","port","label"})
        {
            var r=Capture(new PacketHandler());
            switch(kind)
            {
                case "id":r.Id=Guid.Empty;break;
                case "tls":r.Sni="other.example";break;
                case "udp":r.IsUdp=true;break;
                case "dns":r.DnsIsResponse=true;break;
                case "http":r.HttpMethod="GET";break;
                case "port":r.SourcePort=9601;break;
                case "label":r.ApplicationProtocol="TCP";break;
            }
            Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
        }
    }
    [Fact]
    public async Task CooldownDuplicateReverseAndPeerIsolation()
    {
        var rule=new R983_PrivateFinsNodeNegotiationToPublicClientRule();var first=Capture(new PacketHandler());
        Assert.True((await rule.EvaluateAsync(At(first,100))).Matched);
        Assert.False((await rule.EvaluateAsync(At(first,101))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Capture(new PacketHandler()),99))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(new PacketHandler()),200))).Suppressed);
        Assert.True((await rule.EvaluateAsync(At(Capture(new PacketHandler(),src:"8.8.4.4"),201))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(new PacketHandler()),1000))).Matched);
        Assert.True((await new R983_PrivateFinsNodeNegotiationToPublicClientRule().EvaluateAsync(At(first,100))).Matched);
    }
    [Fact]
    public void RegistryUniqueAndShadow()
    {
        var rules=RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count,rules.Select(r=>r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        var rule=Assert.IsType<R983_PrivateFinsNodeNegotiationToPublicClientRule>(Assert.Single(rules.Where(r=>r.Descriptor.RuleId=="R983")));
        Assert.Equal(RulePrecisionMaturity.Candidate,rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow,rule.PrecisionProfile.DefaultMode);
    }
}
