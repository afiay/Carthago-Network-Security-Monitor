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
public sealed class R967Dnp3UnsolicitedBinaryEventQualityTests
{
    private static readonly DateTime Epoch = new(2026,11,13,0,0,0,DateTimeKind.Utc);
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
    private static byte[] Data(int count = 1)
    {
        var d = new List<byte> { 0xC0, 0xF0, 0x82, 0, 0, 2, 1, 0x17, (byte)count };
        for (int i = 0; i < count; i++) { d.Add((byte)i); d.Add(0x81); }
        return d.ToArray();
    }
    private static byte[] Frame(byte[]? data = null, byte linkControl = 0x44,
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
    public void CrcKnownVector()
    {
        var bytes = Encoding.ASCII.GetBytes("123456789");
        Assert.Equal((ushort)0xEA82, Dnp3UnsolicitedBinaryEventInspector.Crc(bytes));
        Assert.Equal(new byte[] {0x82,0xEA}, Check(bytes));
    }
    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(32)]
    public async Task CompleteCaptureAndEveryCrcBlock(int count)
    {
        var r = Capture(Frame(Data(count)));
        Assert.True(r.Dnp3UnsolicitedBinaryEventObserved);
        var result = await new R967_PublicDnp3UnsolicitedBinaryEventRule().EvaluateAsync(At(r,0));
        Assert.True(result.Matched);
        Assert.DoesNotContain("RAW-INFO-PRIVATE-MARKER",JsonSerializer.Serialize(result.Events));
    }
    [Theory]
    [InlineData("solicited")]
    [InlineData("request")]
    [InlineData("null-response")]
    [InlineData("transport-fragment")]
    [InlineData("app-fragment")]
    [InlineData("no-confirm")]
    [InlineData("wrong-group")]
    [InlineData("wrong-variation")]
    [InlineData("wrong-qualifier")]
    [InlineData("count-mismatch")]
    [InlineData("too-many")]
    [InlineData("wrong-direction")]
    [InlineData("broadcast")]
    [InlineData("same-link-peer")]
    [InlineData("bad-header-crc")]
    [InlineData("bad-data-crc")]
    [InlineData("second-block-crc")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    [InlineData("bad-length")]
    public async Task InvalidOrBenignFramesDoNotMatch(string variant)
    {
        var data=Data();
        switch(variant)
        {
            case "solicited": data[1]=0xE0;data[2]=0x81;break;
            case "request": data[2]=1;break;
            case "null-response": data=data[..5];break;
            case "transport-fragment": data[0]=0x40;break;
            case "app-fragment": data[1]=0xB0;break;
            case "no-confirm": data[1]=0xD0;break;
            case "wrong-group": data[5]=1;break;
            case "wrong-variation": data[6]=2;break;
            case "wrong-qualifier": data[7]=0x28;break;
            case "count-mismatch": data[8]=2;break;
            case "too-many": data=Data(33);break;
            case "second-block-crc": data=Data(8);break;
        }
        byte[] p=variant switch
        {
            "wrong-direction"=>Frame(data,0xC4),
            "broadcast"=>Frame(data,dst:0xFFFF),
            "same-link-peer"=>Frame(data,src:1,dst:1),
            _=>Frame(data)
        };
        switch(variant)
        {
            case "bad-header-crc": p[8]^=1;break;
            case "bad-data-crc": p[^1]^=1;break;
            case "second-block-crc": p[^1]^=1;break;
            case "truncated": p=p[..^1];break;
            case "trailing": p=p.Concat(new byte[]{0}).ToArray();break;
            case "bad-length": p[2]--;break;
        }
        Assert.False(Dnp3UnsolicitedBinaryEventInspector.TryInspect(p));
        var r=Capture(p);
        Assert.False(r.Dnp3UnsolicitedBinaryEventObserved);
        Assert.False((await new R967_PublicDnp3UnsolicitedBinaryEventRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task ScopeAndIncompleteUdpFailClosed()
    {
        foreach(var r in new[] { Capture(src:"10.1.1.10"),Capture(dst:"9.9.9.9"),
            Capture(sport:20001),Capture(dport:20001),Capture(badLength:true) })
            Assert.False((await new R967_PublicDnp3UnsolicitedBinaryEventRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task CaptureFlagCannotBeForgedByJsonOrLabels()
    {
        var forged=JsonSerializer.Deserialize<TrafficRecord>(
            "{\"Dnp3UnsolicitedBinaryEventObserved\":true,\"ApplicationProtocol\":\"dnp3.unsolicited.binary_event\"}")!;
        Assert.False(forged.Dnp3UnsolicitedBinaryEventObserved);
        var r=Capture(new byte[]{1,2,3});
        r.ApplicationProtocol="dnp3.unsolicited.binary_event";r.Info="RAW-INFO-PRIVATE-MARKER";
        Assert.False((await new R967_PublicDnp3UnsolicitedBinaryEventRule().EvaluateAsync(At(r,0))).Matched);
        foreach(var kind in new[]{"tcp","port","id","tls","dns","label"})
        {
            r=Capture();
            switch(kind)
            {
                case "tcp":r.IsTcp=true;break;
                case "port":r.DestinationPort=20001;break;
                case "id":r.Id=Guid.Empty;break;
                case "tls":r.Sni="other.example";break;
                case "dns":r.DnsIsResponse=true;break;
                case "label":r.ApplicationProtocol="UDP";break;
            }
            Assert.False((await new R967_PublicDnp3UnsolicitedBinaryEventRule().EvaluateAsync(At(r,0))).Matched);
        }
    }
    [Fact]
    public async Task DuplicateReverseCooldownAndIsolation()
    {
        var rule=new R967_PublicDnp3UnsolicitedBinaryEventRule();
        var first=Capture();first.Info="RAW-INFO-PRIVATE-MARKER";
        var match=await rule.EvaluateAsync(At(first,100));
        Assert.True(match.Matched);
        Assert.DoesNotContain("RAW-INFO-PRIVATE-MARKER",JsonSerializer.Serialize(match.Events));
        Assert.False((await rule.EvaluateAsync(At(first,101))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Capture(),99))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),200))).Suppressed);
        Assert.True((await rule.EvaluateAsync(At(Capture(dst:"10.1.2.46"),201))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),1000))).Matched);
        Assert.True((await new R967_PublicDnp3UnsolicitedBinaryEventRule().EvaluateAsync(At(Capture(),100))).Matched);
    }
    [Fact]
    public void RegistryUniqueAndShadow()
    {
        var rules=RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count,rules.Select(r=>r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        var rule=Assert.IsType<R967_PublicDnp3UnsolicitedBinaryEventRule>(Assert.Single(rules.Where(r=>r.Descriptor.RuleId=="R967")));
        Assert.Equal(RulePrecisionMaturity.Candidate,rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow,rule.PrecisionProfile.DefaultMode);
    }
}
