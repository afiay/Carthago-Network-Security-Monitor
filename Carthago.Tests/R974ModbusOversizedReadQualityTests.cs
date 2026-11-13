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
public sealed class R974ModbusOversizedReadQualityTests
{
    private static readonly DateTime Epoch=new(2026,11,13,0,0,0,DateTimeKind.Utc);
    private static void U16(byte[] p,int at,ushort v)=>BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(at,2),v);
    private static byte[] Request(ushort quantity=126,ushort transaction=0x1234,byte unit=1)
    {
        var p=new byte[]{0,0,0,0,0,6,unit,3,0,0,0,0};
        U16(p,0,transaction);U16(p,10,quantity);return p;
    }
    private static byte[] Exception(ushort transaction=0x1234,byte unit=1)
    {
        var p=new byte[]{0,0,0,0,0,3,unit,0x83,3};U16(p,0,transaction);return p;
    }
    private static TrafficRecord Parse(PacketHandler h,byte[] data,bool client=true,uint seq=101,
        uint ack=201,byte flags=0x18,int port=51000,string src="8.8.8.8",string dst="10.1.2.45",int service=502)
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
    private static void Syn(PacketHandler h,int port=51000,string src="8.8.8.8",string dst="10.1.2.45",int service=502)
    {
        Parse(h,Array.Empty<byte>(),seq:100,ack:0,flags:2,port:port,src:src,dst:dst,service:service);
        Parse(h,Array.Empty<byte>(),false,200,101,0x12,port,src,dst,service);
    }
    private static TrafficRecord Capture(PacketHandler h,byte[]? request=null,byte[]? response=null,
        string src="8.8.8.8",string dst="10.1.2.45",int service=502)
    {
        var p=request??Request();Syn(h,src:src,dst:dst,service:service);
        Parse(h,p,src:src,dst:dst,service:service);
        return Parse(h,response??Exception(),false,201,101+(uint)p.Length,src:src,dst:dst,service:service);
    }
    private static RuleEvaluationContext At(TrafficRecord r,int s)=>new(r,Sensitivity.Balanced,Epoch.AddSeconds(s));

    [Theory]
    [InlineData(126,0,1)]
    [InlineData(127,1,247)]
    [InlineData(65535,65535,1)]
    public async Task ValidCaptureQuantityAndTransactionBoundaries(int quantity,int transaction,int unit)
    {
        var r=Capture(new PacketHandler(),Request((ushort)quantity,(ushort)transaction,(byte)unit),
            Exception((ushort)transaction,(byte)unit));
        Assert.True(r.ModbusOversizedReadExceptionObserved);
        r.Info="PRIVATE-MODBUS-FIXTURE-MARKER";
        var result=await new R974_PrivateModbusOversizedReadExceptionRule().EvaluateAsync(At(r,0));
        Assert.True(result.Matched);
        Assert.DoesNotContain("PRIVATE-MODBUS-FIXTURE-MARKER",JsonSerializer.Serialize(result.Events));
        Assert.False((await new R968_PublicModbusSameRegisterWriteBurstRule().EvaluateAsync(At(r,0))).Matched);
    }

    [Theory]
    [InlineData("quantity-zero")]
    [InlineData("quantity-one")]
    [InlineData("quantity-125")]
    [InlineData("function-04")]
    [InlineData("function-06")]
    [InlineData("request-protocol")]
    [InlineData("request-length")]
    [InlineData("request-unit-zero")]
    [InlineData("request-unit-248")]
    [InlineData("request-truncated")]
    [InlineData("request-coalesced")]
    [InlineData("transaction-mismatch")]
    [InlineData("unit-mismatch")]
    [InlineData("exception-function")]
    [InlineData("exception-code")]
    [InlineData("response-protocol")]
    [InlineData("response-length")]
    [InlineData("response-truncated")]
    [InlineData("response-coalesced")]
    [InlineData("normal-response")]
    public async Task BenignAndMalformedExchangesFailClosed(string kind)
    {
        var request=Request();var response=Exception();
        switch(kind)
        {
            case "quantity-zero":U16(request,10,0);break;
            case "quantity-one":U16(request,10,1);break;
            case "quantity-125":U16(request,10,125);break;
            case "function-04":request[7]=4;break;
            case "function-06":request[7]=6;break;
            case "request-protocol":U16(request,2,1);break;
            case "request-length":U16(request,4,5);break;
            case "request-unit-zero":request[6]=0;break;
            case "request-unit-248":request[6]=248;break;
            case "request-truncated":request=request[..^1];break;
            case "request-coalesced":request=request.Concat(Request()).ToArray();break;
            case "transaction-mismatch":U16(response,0,0x1235);break;
            case "unit-mismatch":response[6]=2;break;
            case "exception-function":response[7]=0x84;break;
            case "exception-code":response[8]=2;break;
            case "response-protocol":U16(response,2,1);break;
            case "response-length":U16(response,4,4);break;
            case "response-truncated":response=response[..^1];break;
            case "response-coalesced":response=response.Concat(Exception()).ToArray();break;
            case "normal-response":response=new byte[]{0x12,0x34,0,0,0,5,1,3,2,0,1};break;
        }
        var r=Capture(new PacketHandler(),request,response);
        Assert.False(r.ModbusOversizedReadExceptionObserved);
        Assert.False((await new R974_PrivateModbusOversizedReadExceptionRule().EvaluateAsync(At(r,0))).Matched);
    }

    [Theory]
    [InlineData("no-syn")]
    [InlineData("no-synack")]
    [InlineData("no-request")]
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
        DateTime now=Epoch;var h=new PacketHandler(()=>now);var request=Request();
        if(kind=="no-synack")Parse(h,Array.Empty<byte>(),seq:100,ack:0,flags:2);
        else if(kind!="no-syn")Syn(h);
        if(kind!="no-request")Parse(h,request);
        if(kind=="retransmit")Parse(h,request);
        if(kind=="second-client-payload")Parse(h,Request(),seq:113);
        if(kind=="fin")Parse(h,Array.Empty<byte>(),seq:113,flags:0x11);
        if(kind=="reuse")Syn(h);
        if(kind=="expired")now=now.AddSeconds(31);
        if(kind=="reverse-time")now=now.AddSeconds(-1);
        var r=Parse(h,Exception(),false,kind=="gap"?202u:201u,
            kind=="wrong-ack"?112u:113u,port:kind=="other-port"?51001:51000);
        Assert.False(r.ModbusOversizedReadExceptionObserved);
        Assert.False((await new R974_PrivateModbusOversizedReadExceptionRule().EvaluateAsync(At(r,0))).Matched);
    }

    [Fact]
    public async Task ThirtySecondBoundaryAndOneShot()
    {
        DateTime now=Epoch;var h=new PacketHandler(()=>now);Syn(h);Parse(h,Request());
        now=now.AddSeconds(30);
        var first=Parse(h,Exception(),false,201,113);
        Assert.True(first.ModbusOversizedReadExceptionObserved);
        Assert.False(Parse(h,Exception(),false,210,113).ModbusOversizedReadExceptionObserved);
        Assert.True((await new R974_PrivateModbusOversizedReadExceptionRule().EvaluateAsync(At(first,0))).Matched);
    }
    [Fact]
    public async Task ScopeForgeryAndContradictions()
    {
        var rule=new R974_PrivateModbusOversizedReadExceptionRule();
        foreach(var r in new[]{Capture(new PacketHandler(),src:"10.1.1.10"),
            Capture(new PacketHandler(),dst:"9.9.9.9"),Capture(new PacketHandler(),service:503)})
            Assert.False((await rule.EvaluateAsync(At(r,0))).Matched);
        var fake=JsonSerializer.Deserialize<TrafficRecord>("{\"ModbusOversizedReadExceptionObserved\":true}")!;
        Assert.False(fake.ModbusOversizedReadExceptionObserved);
        var label=Parse(new PacketHandler(),Exception(),false);label.ApplicationProtocol="modbus";
        Assert.False((await rule.EvaluateAsync(At(label,0))).Matched);
        foreach(string kind in new[]{"id","tls","udp","dns","http","port","write"})
        {
            var r=Capture(new PacketHandler());
            switch(kind)
            {
                case "id":r.Id=Guid.Empty;break;
                case "tls":r.Sni="other.example";break;
                case "udp":r.IsUdp=true;break;
                case "dns":r.DnsIsResponse=true;break;
                case "http":r.HttpMethod="GET";break;
                case "port":r.SourcePort=503;break;
                case "write":r.ModbusSingleRegisterWritePoint=1;break;
            }
            Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
        }
    }
    [Fact]
    public async Task CooldownDuplicateReverseAndPeerIsolation()
    {
        var rule=new R974_PrivateModbusOversizedReadExceptionRule();var first=Capture(new PacketHandler());
        Assert.True((await rule.EvaluateAsync(At(first,100))).Matched);
        Assert.False((await rule.EvaluateAsync(At(first,101))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Capture(new PacketHandler()),99))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(new PacketHandler()),200))).Suppressed);
        Assert.True((await rule.EvaluateAsync(At(Capture(new PacketHandler(),src:"8.8.4.4"),201))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(new PacketHandler()),1000))).Matched);
        Assert.True((await new R974_PrivateModbusOversizedReadExceptionRule().EvaluateAsync(At(first,100))).Matched);
    }
    [Fact]
    public void RegistryUniqueAndShadow()
    {
        var rules=RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count,rules.Select(r=>r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        var rule=Assert.IsType<R974_PrivateModbusOversizedReadExceptionRule>(Assert.Single(rules.Where(r=>r.Descriptor.RuleId=="R974")));
        Assert.Equal(RulePrecisionMaturity.Candidate,rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow,rule.PrecisionProfile.DefaultMode);
    }
}
