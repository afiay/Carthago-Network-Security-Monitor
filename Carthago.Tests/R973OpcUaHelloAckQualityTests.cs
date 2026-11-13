// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Linq;
using System.Net;
using System.Text;
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
public sealed class R973OpcUaHelloAckQualityTests
{
    private static readonly DateTime Epoch=new(2026,11,13,0,0,0,DateTimeKind.Utc);
    private const string Endpoint="opc.tcp://private-fixture-device:4840/path";
    private static void U32(byte[] p,int at,uint v)=>BinaryPrimitives.WriteUInt32LittleEndian(p.AsSpan(at,4),v);
    private static byte[] Hello(string url=Endpoint,uint receive=8192,uint send=16384)
    {
        var text=Encoding.ASCII.GetBytes(url);var p=new byte[32+text.Length];
        Encoding.ASCII.GetBytes("HELF").CopyTo(p,0);U32(p,4,(uint)p.Length);
        U32(p,12,receive);U32(p,16,send);U32(p,28,(uint)text.Length);text.CopyTo(p,32);return p;
    }
    private static byte[] Ack(uint receive=16384,uint send=8192)
    {
        var p=new byte[28];Encoding.ASCII.GetBytes("ACKF").CopyTo(p,0);U32(p,4,28);
        U32(p,12,receive);U32(p,16,send);return p;
    }
    private static TrafficRecord Parse(PacketHandler h,byte[] data,bool client=true,uint seq=101,
        uint ack=201,byte flags=0x18,int port=51000,string src="8.8.8.8",string dst="10.1.2.45",int service=4840)
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
    private static void Syn(PacketHandler h,int port=51000,string src="8.8.8.8",string dst="10.1.2.45",int service=4840)
    {
        Parse(h,Array.Empty<byte>(),seq:100,ack:0,flags:2,port:port,src:src,dst:dst,service:service);
        Parse(h,Array.Empty<byte>(),false,200,101,0x12,port,src,dst,service);
    }
    private static TrafficRecord Capture(PacketHandler h,byte[]? hello=null,byte[]? response=null,
        string src="8.8.8.8",string dst="10.1.2.45",int service=4840)
    {
        var p=hello??Hello();Syn(h,src:src,dst:dst,service:service);
        Parse(h,p,src:src,dst:dst,service:service);
        return Parse(h,response??Ack(),false,201,101+(uint)p.Length,src:src,dst:dst,service:service);
    }
    private static RuleEvaluationContext At(TrafficRecord r,int s)=>new(r,Sensitivity.Balanced,Epoch.AddSeconds(s));
    [Theory]
    [InlineData(8192,8192)]
    [InlineData(8192,16384)]
    [InlineData(16777216,16777216)]
    public async Task ValidCaptureAndBufferBoundaries(int receive,int send)
    {
        var r=Capture(new PacketHandler(),Hello(receive:(uint)receive,send:(uint)send),Ack((uint)send,(uint)receive));
        Assert.True(r.OpcUaHelloAckObserved);
        r.Info="PRIVATE-OPCUA-FIXTURE-MARKER";
        var result=await new R973_PrivateOpcUaHelloAckToPublicClientRule().EvaluateAsync(At(r,0));
        Assert.True(result.Matched);
        Assert.DoesNotContain("PRIVATE-OPCUA-FIXTURE-MARKER",JsonSerializer.Serialize(result.Events));
        Assert.DoesNotContain(Endpoint,JsonSerializer.Serialize(new{Record=r,result.Events}));
        Assert.False((await new R684_OpcUaPublicClientSynSynAckExchangeRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Theory]
    [InlineData("hello-version")]
    [InlineData("hello-buffer")]
    [InlineData("hello-length")]
    [InlineData("url-length")]
    [InlineData("scheme")]
    [InlineData("userinfo")]
    [InlineData("empty-host")]
    [InlineData("hello-chunk")]
    [InlineData("ack-version")]
    [InlineData("ack-small")]
    [InlineData("ack-big")]
    [InlineData("ack-length")]
    [InlineData("ack-chunk")]
    [InlineData("err")]
    [InlineData("opn")]
    [InlineData("truncated")]
    [InlineData("coalesced")]
    public async Task MalformedAndBenignFramesFailClosed(string kind)
    {
        var hello=Hello();var ack=Ack();
        switch(kind)
        {
            case "hello-version":U32(hello,8,1);break;
            case "hello-buffer":U32(hello,12,8191);break;
            case "hello-length":U32(hello,4,9);break;
            case "url-length":U32(hello,28,uint.MaxValue);break;
            case "scheme":hello=Hello("http://private-fixture-device");break;
            case "userinfo":hello=Hello("opc.tcp://a@private-fixture-device");break;
            case "empty-host":hello=Hello("opc.tcp:///x");break;
            case "hello-chunk":hello[3]=(byte)'C';break;
            case "ack-version":U32(ack,8,1);break;
            case "ack-small":U32(ack,12,8191);break;
            case "ack-big":U32(ack,16,8193);break;
            case "ack-length":U32(ack,4,27);break;
            case "ack-chunk":ack[3]=(byte)'C';break;
            case "err":Encoding.ASCII.GetBytes("ERRF").CopyTo(ack,0);break;
            case "opn":Encoding.ASCII.GetBytes("OPNF").CopyTo(ack,0);break;
            case "truncated":ack=ack[..^1];break;
            case "coalesced":ack=ack.Concat(Ack()).ToArray();break;
        }
        var r=Capture(new PacketHandler(),hello,ack);
        Assert.False(r.OpcUaHelloAckObserved);
        Assert.False((await new R973_PrivateOpcUaHelloAckToPublicClientRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Theory]
    [InlineData("no-syn")]
    [InlineData("no-synack")]
    [InlineData("no-hello")]
    [InlineData("other-port")]
    [InlineData("wrong-ack")]
    [InlineData("gap")]
    [InlineData("retransmit")]
    [InlineData("second-client-payload")]
    [InlineData("fin")]
    [InlineData("reuse")]
    [InlineData("expired")]
    [InlineData("reverse-time")]
    public async Task SessionMismatchAndResetFailClosed(string kind)
    {
        DateTime now=Epoch;var h=new PacketHandler(()=>now);var hello=Hello();
        if(kind=="no-synack")Parse(h,Array.Empty<byte>(),seq:100,ack:0,flags:2);
        else if(kind!="no-syn")Syn(h);
        if(kind!="no-hello")Parse(h,hello);
        if(kind=="retransmit")Parse(h,hello);
        if(kind=="second-client-payload")Parse(h,Hello(),seq:101+(uint)hello.Length);
        if(kind=="fin")Parse(h,Array.Empty<byte>(),seq:101+(uint)hello.Length,flags:0x11);
        if(kind=="reuse")Syn(h);
        if(kind=="expired")now=now.AddSeconds(31);
        if(kind=="reverse-time")now=now.AddSeconds(-1);
        var r=Parse(h,Ack(),false,kind=="gap"?202u:201u,
            101+(uint)hello.Length-(kind=="wrong-ack"?1u:0u),port:kind=="other-port"?51001:51000);
        Assert.False(r.OpcUaHelloAckObserved);
        Assert.False((await new R973_PrivateOpcUaHelloAckToPublicClientRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task ThirtySecondBoundaryAndOneShot()
    {
        DateTime now=Epoch;var h=new PacketHandler(()=>now);var hello=Hello();Syn(h);Parse(h,hello);
        now=now.AddSeconds(30);
        var first=Parse(h,Ack(),false,201,101+(uint)hello.Length);
        Assert.True(first.OpcUaHelloAckObserved);
        Assert.False(Parse(h,Ack(),false,229,101+(uint)hello.Length).OpcUaHelloAckObserved);
        Assert.True((await new R973_PrivateOpcUaHelloAckToPublicClientRule().EvaluateAsync(At(first,0))).Matched);
    }
    [Fact]
    public async Task ScopeForgeryAndContradictions()
    {
        var rule=new R973_PrivateOpcUaHelloAckToPublicClientRule();
        foreach(var r in new[]{Capture(new PacketHandler(),src:"10.1.1.10"),
            Capture(new PacketHandler(),dst:"9.9.9.9"),Capture(new PacketHandler(),service:4841)})
            Assert.False((await rule.EvaluateAsync(At(r,0))).Matched);
        var fake=JsonSerializer.Deserialize<TrafficRecord>("{\"OpcUaHelloAckObserved\":true}")!;
        Assert.False(fake.OpcUaHelloAckObserved);
        var label=Parse(new PacketHandler(),Ack(),false);label.ApplicationProtocol="opcua";
        Assert.False((await rule.EvaluateAsync(At(label,0))).Matched);
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
                case "port":r.SourcePort=4841;break;
            }
            Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
        }
    }
    [Fact]
    public async Task CooldownDuplicateReverseAndPeerIsolation()
    {
        var rule=new R973_PrivateOpcUaHelloAckToPublicClientRule();var first=Capture(new PacketHandler());
        Assert.True((await rule.EvaluateAsync(At(first,100))).Matched);
        Assert.False((await rule.EvaluateAsync(At(first,101))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Capture(new PacketHandler()),99))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(new PacketHandler()),200))).Suppressed);
        Assert.True((await rule.EvaluateAsync(At(Capture(new PacketHandler(),src:"8.8.4.4"),201))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(new PacketHandler()),1000))).Matched);
        Assert.True((await new R973_PrivateOpcUaHelloAckToPublicClientRule().EvaluateAsync(At(first,100))).Matched);
    }
    [Fact]
    public void RegistryUniqueAndShadow()
    {
        var rules=RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count,rules.Select(r=>r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        var rule=Assert.IsType<R973_PrivateOpcUaHelloAckToPublicClientRule>(Assert.Single(rules.Where(r=>r.Descriptor.RuleId=="R973")));
        Assert.Equal(RulePrecisionMaturity.Candidate,rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow,rule.PrecisionProfile.DefaultMode);
    }
}
