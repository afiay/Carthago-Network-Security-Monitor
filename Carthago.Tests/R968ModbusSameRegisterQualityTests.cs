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
public sealed class R968ModbusSameRegisterQualityTests
{
    private static readonly DateTime Epoch = new(2026,11,13,0,0,0,DateTimeKind.Utc);
    private static byte[] Request(ushort register = 0x1234, byte unit = 7, byte function = 6)
    {
        var p = new byte[] {0,1,0,0,0,6,unit,function,0,0,0,1};
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(8,2), register);
        return p;
    }
    private static TrafficRecord Parse(PacketHandler h, byte[] data, int port,
        string src = "8.8.8.8", string dst = "10.1.2.45", byte flags = 0x18,
        uint seq = 101, int dport = 502)
    {
        var p = new byte[40 + data.Length];
        p[0]=0x45;p[8]=64;p[9]=6;
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2,2),(ushort)p.Length);
        IPAddress.Parse(src).GetAddressBytes().CopyTo(p,12);
        IPAddress.Parse(dst).GetAddressBytes().CopyTo(p,16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(20,2),(ushort)port);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(22,2),(ushort)dport);
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(24,4),seq);
        p[32]=0x50;p[33]=flags;data.CopyTo(p,40);
        return Assert.IsType<TrafficRecord>(h.ParseFrame(p,(LinkLayers)12));
    }
    private static TrafficRecord Capture(PacketHandler h, int port, byte[]? data = null,
        string src = "8.8.8.8", string dst = "10.1.2.45", int dport = 502)
    {
        Parse(h,Array.Empty<byte>(),port,src,dst,0x02,100,dport);
        return Parse(h,data ?? Request(),port,src,dst,dport:dport);
    }
    private static RuleEvaluationContext At(TrafficRecord r,double seconds)
        => new(r,Sensitivity.Balanced,Epoch.AddSeconds(seconds));
    private static async Task<RuleEvaluationResult> Burst(IDetectionRule rule, int start,
        int basePort=51000, ushort register=0x1234)
    {
        var h=new PacketHandler(); RuleEvaluationResult? result=null;
        for(int i=0;i<5;i++)
        {
            result=await rule.EvaluateAsync(At(Capture(h,basePort+i,Request(register)),start+i));
            if(i<4) Assert.False(result.Matched);
        }
        return result!;
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65535)]
    public async Task CompleteCaptureFourVersusFiveAndPrivacy(int register)
    {
        var rule=new R968_PublicModbusSameRegisterWriteBurstRule();
        var h=new PacketHandler();
        for(int i=0;i<5;i++)
        {
            var r=Capture(h,51000+i,Request((ushort)register));
            Assert.Equal((uint)((7<<16)|register),r.ModbusSingleRegisterWritePoint);
            r.Info="RAW-PRIVATE-MODBUS-MARKER";
            var result=await rule.EvaluateAsync(At(r,i*2.5));
            Assert.Equal(i==4,result.Matched);
            Assert.DoesNotContain("RAW-PRIVATE-MODBUS-MARKER",JsonSerializer.Serialize(result.Events));
        }
    }
    [Theory]
    [InlineData("read")]
    [InlineData("coil")]
    [InlineData("multiple")]
    [InlineData("exception")]
    [InlineData("protocol")]
    [InlineData("length")]
    [InlineData("zero-unit")]
    [InlineData("high-unit")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    [InlineData("coalesced")]
    public async Task BenignOrMalformedAduCannotContribute(string kind)
    {
        byte[] p=Request();
        switch(kind)
        {
            case "read":p[7]=3;break;
            case "coil":p[7]=5;break;
            case "multiple":p[7]=16;break;
            case "exception":p[7]=0x86;break;
            case "protocol":p[3]=1;break;
            case "length":p[5]=5;break;
            case "zero-unit":p[6]=0;break;
            case "high-unit":p[6]=248;break;
            case "truncated":p=p[..^1];break;
            case "trailing":p=p.Concat(new byte[]{0}).ToArray();break;
            case "coalesced":p=p.Concat(Request()).ToArray();break;
        }
        Assert.False(ModbusSingleRegisterWriteInspector.TryInspect(p,out _));
        var rule=new R968_PublicModbusSameRegisterWriteBurstRule();
        var h=new PacketHandler();
        for(int i=0;i<5;i++)
        {
            var r=Capture(h,51000+i,p);
            Assert.Null(r.ModbusSingleRegisterWritePoint);
            Assert.False((await rule.EvaluateAsync(At(r,i))).Matched);
        }
    }
    [Fact]
    public async Task MissingSynGapRetransmissionAndLaterPayloadFailClosed()
    {
        var h=new PacketHandler();
        Assert.Null(Parse(h,Request(),51000).ModbusSingleRegisterWritePoint);
        Parse(h,Array.Empty<byte>(),51001,flags:0x02,seq:100);
        Assert.Null(Parse(h,Request(),51001,seq:102).ModbusSingleRegisterWritePoint);
        var first=Capture(h,51002);
        Assert.NotNull(first.ModbusSingleRegisterWritePoint);
        Assert.Null(Parse(h,Request(),51002).ModbusSingleRegisterWritePoint);
        Assert.Null(Parse(h,Request(),51002,seq:113).ModbusSingleRegisterWritePoint);
        Parse(h,Array.Empty<byte>(),51003,flags:0x02,seq:100);
        Assert.Null(Parse(h,Request(function:3),51003).ModbusSingleRegisterWritePoint);
        Assert.Null(Parse(h,Request(),51003,seq:113).ModbusSingleRegisterWritePoint);
        var rule=new R968_PublicModbusSameRegisterWriteBurstRule();
        for(int i=0;i<5;i++) Assert.False((await rule.EvaluateAsync(At(first,i))).Matched);
    }
    [Theory]
    [InlineData("register")]
    [InlineData("unit")]
    [InlineData("destination")]
    [InlineData("source")]
    [InlineData("port")]
    [InlineData("private")]
    [InlineData("wrong-service")]
    [InlineData("late")]
    [InlineData("reverse")]
    public async Task DifferentPointsPeersPortsAndTimeCannotCombine(string kind)
    {
        var h=new PacketHandler();var rule=new R968_PublicModbusSameRegisterWriteBurstRule();
        for(int i=0;i<5;i++)
        {
            var r=Capture(h,kind=="port"?51000:51000+i,
                Request(kind=="register"?(ushort)i:(ushort)42,kind=="unit"?(byte)(1+i):(byte)7),
                kind=="private"?"10.1.1.10":kind=="source"?"8.8.8."+(i+1):"8.8.8.8",
                kind=="destination"?"10.1.2."+(i+1):"10.1.2.45",kind=="wrong-service"?503:502);
            double seconds=kind=="late"?i*3:kind=="reverse"?10-i:i;
            Assert.False((await rule.EvaluateAsync(At(r,seconds))).Matched);
        }
    }
    [Fact]
    public async Task JsonLabelsAndContradictionsCannotSubstituteForCapture()
    {
        var fake=JsonSerializer.Deserialize<TrafficRecord>(
            "{\"ModbusSingleRegisterWritePoint\":458794,\"ApplicationProtocol\":\"modbus.write\"}")!;
        Assert.Null(fake.ModbusSingleRegisterWritePoint);
        var rule=new R968_PublicModbusSameRegisterWriteBurstRule();
        var h=new PacketHandler();
        for(int i=0;i<5;i++)
        {
            var r=Capture(h,51000+i,Request(function:3));
            r.ApplicationProtocol="modbus.write";r.Info="Modbus write register";
            Assert.False((await rule.EvaluateAsync(At(r,i))).Matched);
        }
        foreach(var kind in new[]{"id","udp","tls","http","dns","port"})
        {
            for(int i=0;i<5;i++)
            {
                var r=Capture(new PacketHandler(),52000+i);
                switch(kind)
                {
                    case "id":r.Id=Guid.Empty;break;
                    case "udp":r.IsUdp=true;break;
                    case "tls":r.Sni="test.example";break;
                    case "http":r.HttpMethod="GET";break;
                    case "dns":r.DnsIsResponse=true;break;
                    case "port":r.DestinationPort=503;break;
                }
                Assert.False((await rule.EvaluateAsync(At(r,20+i))).Matched);
            }
        }
    }
    [Fact]
    public async Task CooldownRecoveryAndIndependentInstances()
    {
        var rule=new R968_PublicModbusSameRegisterWriteBurstRule();
        Assert.True((await Burst(rule,0)).Matched);
        Assert.True((await Burst(rule,20,52000)).Suppressed);
        Assert.True((await Burst(rule,40,53000,0x1235)).Matched);
        Assert.True((await Burst(rule,700,54000)).Matched);
        Assert.True((await Burst(new R968_PublicModbusSameRegisterWriteBurstRule(),0)).Matched);
    }
    [Fact]
    public void RegistryUniqueAndShadow()
    {
        var rules=RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count,rules.Select(r=>r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        var rule=Assert.IsType<R968_PublicModbusSameRegisterWriteBurstRule>(Assert.Single(rules.Where(r=>r.Descriptor.RuleId=="R968")));
        Assert.Equal(RulePrecisionMaturity.Candidate,rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow,rule.PrecisionProfile.DefaultMode);
    }
}
