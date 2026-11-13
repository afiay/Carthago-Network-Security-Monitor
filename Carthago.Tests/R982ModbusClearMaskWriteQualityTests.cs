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
public sealed class R982ModbusClearMaskWriteQualityTests
{
    private static readonly DateTime Epoch=new(2026,11,13,0,0,0,DateTimeKind.Utc);
    private static void U16(byte[] p,int at,ushort v)=>BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(at,2),v);
    private static byte[] Request(ushort transaction=0x1234,byte unit=1,ushort register=0)
    {
        var p=new byte[]{0,0,0,0,0,8,unit,0x16,0,0,0,0,0,0};
        U16(p,0,transaction);U16(p,8,register);return p;
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

    private static TrafficRecord Capture(byte[]? data=null,string src="8.8.8.8",string dst="10.1.2.45",int service=502)
    {
        var h=new PacketHandler();Syn(h,src:src,dst:dst,service:service);
        return Parse(h,data??Request(),src:src,dst:dst,service:service);
    }
    private static RuleEvaluationContext At(TrafficRecord r,int s)=>new(r,Sensitivity.Balanced,Epoch.AddSeconds(s));
    [Theory]
    [InlineData(0,1,0)]
    [InlineData(65535,247,65535)]
    [InlineData(1234,7,4096)]
    public async Task CaptureValidTransactionUnitRegisterBounds(int tx,int unit,int register)
    {
        var r=Capture(Request((ushort)tx,(byte)unit,(ushort)register));
        Assert.True(r.ModbusClearMaskWriteObserved);
        Assert.Null(r.ModbusSingleRegisterWritePoint);
        r.Info="PRIVATE-MASK-WRITE-FIXTURE";
        var result=await new R982_PublicModbusClearMaskWriteRule().EvaluateAsync(At(r,0));
        Assert.True(result.Matched);
        Assert.DoesNotContain("PRIVATE-MASK-WRITE-FIXTURE",JsonSerializer.Serialize(result.Events));
        Assert.False((await new R968_PublicModbusSameRegisterWriteBurstRule().EvaluateAsync(At(r,0))).Matched);
        Assert.False((await new R974_PrivateModbusOversizedReadExceptionRule().EvaluateAsync(At(r,0))).Matched);
        Assert.False((await new R978_PrivateModbusBulkFileReadResponseRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Theory]
    [InlineData("and-one")]
    [InlineData("or-one")]
    [InlineData("and-all")]
    [InlineData("ordinary-mask")]
    [InlineData("read")]
    [InlineData("single-write")]
    [InlineData("multiple-write")]
    [InlineData("exception")]
    [InlineData("protocol")]
    [InlineData("length")]
    [InlineData("unit-zero")]
    [InlineData("unit-248")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    [InlineData("coalesced")]
    public async Task BenignAndMalformedRequestsFailClosed(string kind)
    {
        var p=Request();
        switch(kind)
        {
            case "and-one":U16(p,10,1);break;
            case "or-one":U16(p,12,1);break;
            case "and-all":U16(p,10,65535);break;
            case "ordinary-mask":U16(p,10,0xFFF0);U16(p,12,3);break;
            case "read":p[7]=3;break;
            case "single-write":p[7]=6;break;
            case "multiple-write":p[7]=16;break;
            case "exception":p[7]=0x96;break;
            case "protocol":U16(p,2,1);break;
            case "length":U16(p,4,7);break;
            case "unit-zero":p[6]=0;break;
            case "unit-248":p[6]=248;break;
            case "truncated":p=p[..^1];break;
            case "trailing":p=p.Concat(new byte[]{0}).ToArray();break;
            case "coalesced":p=p.Concat(Request()).ToArray();break;
        }
        Assert.False(ModbusClearMaskWriteInspector.TryInspect(p));
        var r=Capture(p);
        Assert.False(r.ModbusClearMaskWriteObserved);
        Assert.False((await new R982_PublicModbusClearMaskWriteRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task MissingSynResponseRetransmitGapAndSecondPayload()
    {
        var noSyn=Parse(new PacketHandler(),Request());
        Assert.False(noSyn.ModbusClearMaskWriteObserved);
        var h=new PacketHandler();Syn(h);
        Assert.True(Parse(h,Request()).ModbusClearMaskWriteObserved);
        Assert.False(Parse(h,Request()).ModbusClearMaskWriteObserved);
        Assert.False(Parse(h,Request(),false,201,115).ModbusClearMaskWriteObserved);
        h=new PacketHandler();Syn(h);
        Assert.False(Parse(h,Request(),seq:102).ModbusClearMaskWriteObserved);
        h=new PacketHandler();Syn(h);Parse(h,new byte[]{1,2,3});
        Assert.False(Parse(h,Request(),seq:104).ModbusClearMaskWriteObserved);
        h=new PacketHandler();Syn(h);
        Assert.False(Parse(h,Request(),flags:0x10).ModbusClearMaskWriteObserved);
        h=new PacketHandler();Syn(h);
        Assert.False(Parse(h,Request()[..7]).ModbusClearMaskWriteObserved);
        Assert.False(Parse(h,Request()[7..],seq:108).ModbusClearMaskWriteObserved);
        foreach(var r in new[]{noSyn,Capture(src:"10.1.1.10"),Capture(dst:"9.9.9.9"),Capture(service:503)})
            Assert.False((await new R982_PublicModbusClearMaskWriteRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task ScopeAndDatagramIntegrity()
    {
        var h=new PacketHandler();Syn(h,port:502);
        Assert.False(Parse(h,Request(),port:502).ModbusClearMaskWriteObserved);
        // Complete IP length is checked independently of MBAP length.
        h=new PacketHandler();Syn(h);
        var p=new byte[40+14];p[0]=0x45;p[8]=64;p[9]=6;
        U16(p,2,(ushort)(p.Length+1));
        IPAddress.Parse("8.8.8.8").GetAddressBytes().CopyTo(p,12);
        IPAddress.Parse("10.1.2.45").GetAddressBytes().CopyTo(p,16);
        U16(p,20,51000);U16(p,22,502);
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(24,4),101);
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(28,4),201);
        p[32]=0x50;p[33]=0x18;Request().CopyTo(p,40);
        var r=h.ParseFrame(p,(LinkLayers)12);
        if(r!=null)
        {
            Assert.False(r.ModbusClearMaskWriteObserved);
            Assert.False((await new R982_PublicModbusClearMaskWriteRule().EvaluateAsync(At(r,0))).Matched);
        }
    }
    [Fact]
    public async Task ForgedAndContradictoryFieldsCannotReplaceProof()
    {
        var fake=JsonSerializer.Deserialize<TrafficRecord>("{\"ModbusClearMaskWriteObserved\":true}")!;
        Assert.False(fake.ModbusClearMaskWriteObserved);
        var rule=new R982_PublicModbusClearMaskWriteRule();
        var label=Capture(new byte[]{1,2,3});label.ApplicationProtocol="modbus";
        Assert.False((await rule.EvaluateAsync(At(label,0))).Matched);
        foreach(string kind in new[]{"id","udp","tls","dns","http","port","write","exception","bulk"})
        {
            var r=Capture();
            switch(kind)
            {
                case "id":r.Id=Guid.Empty;break;
                case "udp":r.IsUdp=true;break;
                case "tls":r.Sni="other.example";break;
                case "dns":r.DnsIsResponse=true;break;
                case "http":r.HttpUri="/admin";break;
                case "port":r.DestinationPort=503;break;
                case "write":r.ModbusSingleRegisterWritePoint=1;break;
                case "exception":r.ModbusOversizedReadExceptionObserved=true;break;
                case "bulk":r.ModbusBulkFileReadResponseObserved=true;break;
            }
            Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
        }
    }
    [Fact]
    public async Task DuplicateReverseCooldownAndPeerIsolation()
    {
        var rule=new R982_PublicModbusClearMaskWriteRule();var first=Capture();
        Assert.True((await rule.EvaluateAsync(At(first,100))).Matched);
        Assert.False((await rule.EvaluateAsync(At(first,101))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Capture(),99))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),200))).Suppressed);
        Assert.True((await rule.EvaluateAsync(At(Capture(dst:"10.1.2.46"),201))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),1000))).Matched);
        Assert.True((await new R982_PublicModbusClearMaskWriteRule().EvaluateAsync(At(first,100))).Matched);
    }
    [Fact]
    public void RegistryUniqueAndShadow()
    {
        var rules=RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count,rules.Select(r=>r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        var rule=Assert.IsType<R982_PublicModbusClearMaskWriteRule>(Assert.Single(rules.Where(r=>r.Descriptor.RuleId=="R982")));
        Assert.Equal(RulePrecisionMaturity.Candidate,rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow,rule.PrecisionProfile.DefaultMode);
    }
}
