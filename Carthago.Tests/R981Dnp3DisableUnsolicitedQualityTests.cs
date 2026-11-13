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
public sealed class R981Dnp3DisableUnsolicitedQualityTests
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
    private static byte[] Data(byte a=2,byte b=3,byte c=4)
        => new byte[]{0xC0,0xC0,0x15,60,a,6,60,b,6,60,c,6};
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



    [Theory]
    [InlineData(2,3,4)]
    [InlineData(2,4,3)]
    [InlineData(3,2,4)]
    [InlineData(3,4,2)]
    [InlineData(4,2,3)]
    [InlineData(4,3,2)]
    public async Task CompleteCaptureAllClassPermutations(int a,int b,int c)
    {
        var r=Capture(Frame(Data((byte)a,(byte)b,(byte)c)));
        Assert.True(r.Dnp3DisableUnsolicitedObserved);
        Assert.False(r.Dnp3UnsolicitedBinaryEventObserved);
        Assert.False(r.Dnp3RestartRequestObserved);
        Assert.Equal("dnp3.disable_unsolicited.request",r.ApplicationProtocol);
        r.Info="PRIVATE-DNP3-DISABLE-MARKER";
        var result=await new R981_PublicDnp3DisableUnsolicitedRule().EvaluateAsync(At(r,0));
        Assert.True(result.Matched);
        Assert.DoesNotContain("PRIVATE-DNP3-DISABLE-MARKER",JsonSerializer.Serialize(result.Events));
        Assert.False((await new R967_PublicDnp3UnsolicitedBinaryEventRule().EvaluateAsync(At(r,0))).Matched);
        Assert.False((await new R980_PublicDnp3RestartRequestRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Theory]
    [InlineData("enable")]
    [InlineData("read")]
    [InlineData("restart")]
    [InlineData("response")]
    [InlineData("class-zero")]
    [InlineData("duplicate")]
    [InlineData("partial")]
    [InlineData("extra")]
    [InlineData("wrong-group")]
    [InlineData("wrong-qualifier")]
    [InlineData("wrong-direction")]
    [InlineData("confirmed-link")]
    [InlineData("transport-fragment")]
    [InlineData("app-fragment")]
    [InlineData("app-confirm")]
    [InlineData("app-unsolicited")]
    [InlineData("broadcast")]
    [InlineData("reserved-source")]
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
            case "enable":data[2]=0x14;break;
            case "read":data[2]=1;break;
            case "restart":data[2]=0x0D;break;
            case "response":data[2]=0x81;break;
            case "class-zero":data[4]=1;break;
            case "duplicate":data[7]=2;break;
            case "partial":data=data[..9];break;
            case "extra":data=data.Concat(new byte[]{60,1,6}).ToArray();break;
            case "wrong-group":data[6]=61;break;
            case "wrong-qualifier":data[8]=7;break;
            case "transport-fragment":data[0]=0x40;break;
            case "app-fragment":data[1]=0x80;break;
            case "app-confirm":data[1]=0xE0;break;
            case "app-unsolicited":data[1]=0xD0;break;
        }
        byte[] p=kind switch
        {
            "wrong-direction"=>Frame(data,0x44),
            "confirmed-link"=>Frame(data,0xD3),
            "broadcast"=>Frame(data,dst:0xFFFF),
            "reserved-source"=>Frame(data,src:0xFFF0),
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
        Assert.False(Dnp3DisableUnsolicitedInspector.TryInspect(p));
        var r=Capture(p);
        Assert.False(r.Dnp3DisableUnsolicitedObserved);
        Assert.False((await new R981_PublicDnp3DisableUnsolicitedRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task ScopeAndDatagramIntegrity()
    {
        foreach(var r in new[]{Capture(src:"10.1.1.10"),Capture(dst:"9.9.9.9"),
            Capture(sport:20001),Capture(dport:20001),Capture(badLength:true)})
            Assert.False((await new R981_PublicDnp3DisableUnsolicitedRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task UnsolicitedEventIsNotDisable()
    {
        var r=Capture(Frame(new byte[]{0xC0,0xF0,0x82,0,0,2,1,0x17,1,0,0x81},0x44));
        Assert.True(r.Dnp3UnsolicitedBinaryEventObserved);
        Assert.False(r.Dnp3DisableUnsolicitedObserved);
        Assert.False((await new R981_PublicDnp3DisableUnsolicitedRule().EvaluateAsync(At(r,0))).Matched);
        Assert.True((await new R967_PublicDnp3UnsolicitedBinaryEventRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task LabelsAndContradictoryFieldsCannotReplaceProof()
    {
        var fake=JsonSerializer.Deserialize<TrafficRecord>("{\"Dnp3DisableUnsolicitedObserved\":true}")!;
        Assert.False(fake.Dnp3DisableUnsolicitedObserved);
        var label=Capture(new byte[]{1,2,3});label.ApplicationProtocol="dnp3.disable_unsolicited.request";
        var rule=new R981_PublicDnp3DisableUnsolicitedRule();
        Assert.False((await rule.EvaluateAsync(At(label,0))).Matched);
        foreach(string kind in new[]{"id","tcp","tls","dns","http","port","label","unsolicited","restart"})
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
                case "restart":r.Dnp3RestartRequestObserved=true;break;
            }
            Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
        }
    }
    [Fact]
    public async Task DuplicateReverseCooldownAndPeerIsolation()
    {
        var rule=new R981_PublicDnp3DisableUnsolicitedRule();var first=Capture();
        Assert.True((await rule.EvaluateAsync(At(first,100))).Matched);
        Assert.False((await rule.EvaluateAsync(At(first,101))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Capture(),99))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),200))).Suppressed);
        Assert.True((await rule.EvaluateAsync(At(Capture(dst:"10.1.2.46"),201))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),1000))).Matched);
        Assert.True((await new R981_PublicDnp3DisableUnsolicitedRule().EvaluateAsync(At(first,100))).Matched);
    }
    [Fact]
    public void RegistryUniqueAndShadow()
    {
        var rules=RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count,rules.Select(r=>r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        var rule=Assert.IsType<R981_PublicDnp3DisableUnsolicitedRule>(Assert.Single(rules.Where(r=>r.Descriptor.RuleId=="R981")));
        Assert.Equal(RulePrecisionMaturity.Candidate,rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow,rule.PrecisionProfile.DefaultMode);
    }
}
