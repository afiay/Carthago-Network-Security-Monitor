// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests;
public sealed class R980Dnp3RestartQualityTests
{
    private static readonly DateTime Epoch=new(2026,11,13,0,0,0,DateTimeKind.Utc);
    // Independent MSB-first CRC-16/DNP calculation: reverse each byte, use
    // normal polynomial 0x3D65, reverse final register and complement.
    private static uint Reverse(uint x, int width)
    {
        uint result = 0;
        for (int i = 0; i < width; i++) { result = (result << 1) | (x & 1); x >>= 1; }
        return result;
    }
    private static byte[] Check(IEnumerable<byte> bytes)
    {
        uint crc = 0;
        foreach (byte b in bytes)
        {
            crc ^= Reverse(b,8) << 8;
            for (int bit = 0; bit < 8; bit++)
                crc = ((crc << 1) ^ ((crc & 0x8000) != 0 ? 0x3D65u : 0u)) & 0xFFFF;
        }
        uint result = Reverse(crc,16) ^ 0xFFFF;
        return new[] { (byte)result, (byte)(result >> 8) };
    }
    private static byte[] Data(byte function=0x0D,byte transport=0xC0,byte application=0xC0)
        => new byte[]{transport,application,function};
    private static byte[] Frame(byte[]? data = null, byte linkControl = 0xC4,
        ushort src = 7, ushort dst = 1)
    {
        data ??= Data();
        var header = new byte[] { 5,0x64,(byte)(5 + data.Length),linkControl,
            (byte)dst,(byte)(dst>>8),(byte)src,(byte)(src>>8) };
        var frame = new List<byte>(header); frame.AddRange(Check(header));
        for (int pos = 0; pos < data.Length; pos += 16)
        {
            var block = data.Skip(pos).Take(16).ToArray();
            frame.AddRange(block); frame.AddRange(Check(block));
        }
        return frame.ToArray();
    }
    private static TrafficRecord Capture(byte[]? payload = null, string src = "8.8.8.8",
        string dst = "10.1.2.45", int sport = 20000, int dport = 20000, bool badLength = false)
        => TftpCaptureQualificationTests.Parse(new PacketHandler(),src,dst,sport,dport,
            payload ?? Frame(),badLength);
    private static RuleEvaluationContext At(TrafficRecord r,int second)
        => new(r,Sensitivity.Balanced,Epoch.AddSeconds(second));


    [Fact]
    public void IndependentCrcKnownVector()
    {
        var bytes=Encoding.ASCII.GetBytes("123456789");
        Assert.Equal(new byte[]{0x82,0xEA},Check(bytes));
        Assert.Equal((ushort)0xEA82,Dnp3UnsolicitedBinaryEventInspector.Crc(bytes));
    }
    [Theory]
    [InlineData(0x0D,0xC0,0xC0,0,1)]
    [InlineData(0x0E,0xFF,0xCF,7,0xFFEF)]
    [InlineData(0x0D,0xC1,0xC5,0xFFEF,0)]
    [InlineData(0x0E,0xD0,0xCA,7,1)]
    public async Task CompleteCaptureFunctionAndSequenceBoundaries(int function,int transport,int application,int source,int destination)
    {
        var r=Capture(Frame(Data((byte)function,(byte)transport,(byte)application),src:(ushort)source,dst:(ushort)destination));
        Assert.True(r.Dnp3RestartRequestObserved);
        Assert.False(r.Dnp3UnsolicitedBinaryEventObserved);
        Assert.Equal("dnp3.restart.request",r.ApplicationProtocol);
        r.Info="PRIVATE-DNP3-RESTART-MARKER";
        var match=await new R980_PublicDnp3RestartRequestRule().EvaluateAsync(At(r,0));
        Assert.True(match.Matched);
        Assert.DoesNotContain("PRIVATE-DNP3-RESTART-MARKER",JsonSerializer.Serialize(match.Events));
        Assert.False((await new R967_PublicDnp3UnsolicitedBinaryEventRule().EvaluateAsync(At(r,0))).Matched);
        Assert.False((await new R975_PublicBacnetReinitializeDeviceRequestRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Theory]
    [InlineData("read")]
    [InlineData("write")]
    [InlineData("select")]
    [InlineData("operate")]
    [InlineData("response")]
    [InlineData("unsolicited")]
    [InlineData("wrong-direction")]
    [InlineData("confirmed-link")]
    [InlineData("link-status")]
    [InlineData("transport-first-only")]
    [InlineData("transport-final-only")]
    [InlineData("app-first-only")]
    [InlineData("app-final-only")]
    [InlineData("app-confirm")]
    [InlineData("app-unsolicited")]
    [InlineData("extra-object")]
    [InlineData("broadcast")]
    [InlineData("reserved-source")]
    [InlineData("reserved-destination")]
    [InlineData("same-link-peer")]
    [InlineData("bad-header-crc")]
    [InlineData("bad-data-crc")]
    [InlineData("bad-length")]
    [InlineData("bad-sync")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    public async Task OtherOperationsAndMalformedFramesFailClosed(string kind)
    {
        var data=Data();
        switch(kind)
        {
            case "read":data[2]=1;break;
            case "write":data[2]=2;break;
            case "select":data[2]=3;break;
            case "operate":data[2]=4;break;
            case "response":data[2]=0x81;break;
            case "unsolicited":data[2]=0x82;break;
            case "transport-first-only":data[0]=0x40;break;
            case "transport-final-only":data[0]=0x80;break;
            case "app-first-only":data[1]=0x80;break;
            case "app-final-only":data[1]=0x40;break;
            case "app-confirm":data[1]=0xE0;break;
            case "app-unsolicited":data[1]=0xD0;break;
            case "extra-object":data=data.Concat(new byte[]{60,1,6}).ToArray();break;
        }
        byte[] p=kind switch
        {
            "wrong-direction"=>Frame(data,0x44),
            "confirmed-link"=>Frame(data,0xD3),
            "link-status"=>Frame(data,0xC9),
            "broadcast"=>Frame(data,dst:0xFFFF),
            "reserved-source"=>Frame(data,src:0xFFF0),
            "reserved-destination"=>Frame(data,dst:0xFFF0),
            "same-link-peer"=>Frame(data,src:1,dst:1),
            _=>Frame(data)
        };
        switch(kind)
        {
            case "bad-header-crc":p[8]^=1;break;
            case "bad-data-crc":p[^1]^=1;break;
            case "bad-length":p[2]--;break;
            case "bad-sync":p[0]=6;break;
            case "truncated":p=p[..^1];break;
            case "trailing":p=p.Concat(new byte[]{0}).ToArray();break;
        }
        Assert.False(Dnp3RestartRequestInspector.TryInspect(p));
        var r=Capture(p);
        Assert.False(r.Dnp3RestartRequestObserved);
        Assert.False((await new R980_PublicDnp3RestartRequestRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task ScopeAndDatagramIntegrity()
    {
        foreach(var r in new[]{Capture(src:"10.1.1.10"),Capture(dst:"9.9.9.9"),
            Capture(sport:20001),Capture(dport:20001),Capture(badLength:true)})
            Assert.False((await new R980_PublicDnp3RestartRequestRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task UnsolicitedEventIsNotRestart()
    {
        var r=Capture(Frame(new byte[]{0xC0,0xF0,0x82,0,0,2,1,0x17,1,0,0x81},0x44));
        Assert.True(r.Dnp3UnsolicitedBinaryEventObserved);
        Assert.False(r.Dnp3RestartRequestObserved);
        Assert.False((await new R980_PublicDnp3RestartRequestRule().EvaluateAsync(At(r,0))).Matched);
        Assert.True((await new R967_PublicDnp3UnsolicitedBinaryEventRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task LabelsAndContradictoryFieldsCannotReplaceProof()
    {
        var fake=JsonSerializer.Deserialize<TrafficRecord>("{\"Dnp3RestartRequestObserved\":true}")!;
        Assert.False(fake.Dnp3RestartRequestObserved);
        var label=Capture(new byte[]{1,2,3});label.ApplicationProtocol="dnp3.restart.request";
        var rule=new R980_PublicDnp3RestartRequestRule();
        Assert.False((await rule.EvaluateAsync(At(label,0))).Matched);
        foreach(string kind in new[]{"id","tcp","tls","dns","http","port","label","unsolicited"})
        {
            var r=Capture();
            switch(kind)
            {
                case "id":r.Id=Guid.Empty;break;
                case "tcp":r.IsTcp=true;break;
                case "tls":r.Sni="other.example";break;
                case "dns":r.DnsIsResponse=true;break;
                case "http":r.HttpUri="/admin";break;
                case "port":r.DestinationPort=20001;break;
                case "label":r.ApplicationProtocol="UDP";break;
                case "unsolicited":r.Dnp3UnsolicitedBinaryEventObserved=true;break;
            }
            Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
        }
    }
    [Fact]
    public async Task DuplicateReverseCooldownAndPeerIsolation()
    {
        var rule=new R980_PublicDnp3RestartRequestRule();var first=Capture();
        Assert.True((await rule.EvaluateAsync(At(first,100))).Matched);
        Assert.False((await rule.EvaluateAsync(At(first,101))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Capture(),99))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),200))).Suppressed);
        Assert.True((await rule.EvaluateAsync(At(Capture(dst:"10.1.2.46"),201))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),1000))).Matched);
        Assert.True((await new R980_PublicDnp3RestartRequestRule().EvaluateAsync(At(first,100))).Matched);
    }
    [Fact]
    public void RegistryUniqueAndShadow()
    {
        var rules=RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count,rules.Select(r=>r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        var rule=Assert.IsType<R980_PublicDnp3RestartRequestRule>(Assert.Single(rules.Where(r=>r.Descriptor.RuleId=="R980")));
        Assert.Equal(RulePrecisionMaturity.Candidate,rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow,rule.PrecisionProfile.DefaultMode);
    }
}
