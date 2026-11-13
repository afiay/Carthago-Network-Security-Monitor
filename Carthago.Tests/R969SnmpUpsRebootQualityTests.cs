// SPDX-License-Identifier: MIT
using System;
using System.Linq;
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
public sealed class R969SnmpUpsRebootQualityTests
{
    private static readonly DateTime Epoch = new(2026,11,13,0,0,0,DateTimeKind.Utc);
    private const string Community = "private-ups-community-fixture";
    private static byte[] Oid() => new byte[]{0x2B,6,1,2,1,33,1,8,4,0};
    private static byte[] Tlv(byte tag, params byte[][] fields)
    {
        var b=fields.SelectMany(x=>x).ToArray();
        byte[] len=b.Length<128?new[]{(byte)b.Length}:b.Length<=255?
            new[]{(byte)0x81,(byte)b.Length}:new[]{(byte)0x82,(byte)(b.Length>>8),(byte)b.Length};
        return new[]{tag}.Concat(len).Concat(b).ToArray();
    }
    private static byte[] I(params byte[] b)=>Tlv(2,b);
    private static byte[] Message(byte version=1,byte pdu=0xA3,byte[]? oid=null,
        byte[]? value=null,int count=1,byte error=0,byte index=0)
    {
        var binding=Tlv(0x30,Tlv(6,oid??Oid()),value??I(60));
        return Tlv(0x30,I(version),Tlv(4,Encoding.ASCII.GetBytes(Community)),
            Tlv(pdu,I(7),I(error),I(index),Tlv(0x30,Enumerable.Repeat(binding,count).ToArray())));
    }
    private static TrafficRecord Capture(byte[]? payload=null,string src="8.8.8.8",
        string dst="10.1.2.45",int port=161,bool badLength=false)
        =>TftpCaptureQualificationTests.Parse(new PacketHandler(),src,dst,51000,port,payload??Message(),badLength);
    private static RuleEvaluationContext At(TrafficRecord r,int second)
        =>new(r,Sensitivity.Balanced,Epoch.AddSeconds(second));

    [Theory]
    [InlineData((byte)0,"00")]
    [InlineData((byte)1,"7F")]
    [InlineData((byte)1,"0080")]
    [InlineData((byte)1,"7FFFFFFF")]
    public async Task ExactCaptureAndIntegerBoundaries(byte version,string duration)
    {
        var r=Capture(Message(version:version,value:I(Convert.FromHexString(duration))));
        Assert.True(r.SnmpUpsRebootRequestObserved);
        Assert.False(r.SnmpEnterpriseSetRequestObserved);
        var match=await new R969_PublicSnmpUpsRebootRequestRule().EvaluateAsync(At(r,0));
        Assert.True(match.Matched);
        Assert.False((await new R966_PublicSnmpEnterpriseSetRequestRule().EvaluateAsync(At(r,0))).Matched);
        r.Info="RAW-PRIVATE-UPS-MARKER";
        Assert.DoesNotContain("RAW-PRIVATE-UPS-MARKER",JsonSerializer.Serialize(match.Events));
        Assert.DoesNotContain(Community,JsonSerializer.Serialize(new { Record=r,match.Events }));
    }

    [Theory]
    [InlineData("get")]
    [InlineData("getnext")]
    [InlineData("response")]
    [InlineData("enterprise")]
    [InlineData("shutdown")]
    [InlineData("startup")]
    [InlineData("missing-scalar")]
    [InlineData("wrong-index")]
    [InlineData("negative")]
    [InlineData("nonminimal")]
    [InlineData("overflow")]
    [InlineData("empty-integer")]
    [InlineData("string")]
    [InlineData("null")]
    [InlineData("mixed-count")]
    [InlineData("empty-list")]
    [InlineData("v3")]
    [InlineData("error")]
    [InlineData("index")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    public async Task OtherCommandsAndMalformedEvidenceDoNotMatch(string kind)
    {
        byte[] o=Oid();
        if(kind=="shutdown")o[8]=2;
        if(kind=="startup")o[8]=3;
        if(kind=="wrong-index")o[9]=1;
        byte[] p=kind switch
        {
            "get"=>Message(pdu:0xA0,value:Tlv(5)),
            "getnext"=>Message(pdu:0xA1,value:Tlv(5)),
            "response"=>Message(pdu:0xA2),
            "enterprise"=>Message(oid:new byte[]{0x2B,6,1,4,1,9,1}),
            "shutdown" or "startup" or "wrong-index"=>Message(oid:o),
            "missing-scalar"=>Message(oid:o[..^1]),
            "negative"=>Message(value:I(0xFF)),
            "nonminimal"=>Message(value:I(0,1)),
            "overflow"=>Message(value:I(0,0x80,0,0,0)),
            "empty-integer"=>Message(value:I()),
            "string"=>Message(value:Tlv(4,new byte[]{60})),
            "null"=>Message(value:Tlv(5)),
            "mixed-count"=>Message(count:2),
            "empty-list"=>Message(count:0),
            "v3"=>Message(version:3),
            "error"=>Message(error:1),
            "index"=>Message(index:1),
            "truncated"=>Message()[..^1],
            _=>Message().Concat(new byte[]{0}).ToArray()
        };
        Assert.False(SnmpEnterpriseSetInspector.TryInspectUpsReboot(p));
        var r=Capture(p);
        Assert.False(r.SnmpUpsRebootRequestObserved);
        Assert.False((await new R969_PublicSnmpUpsRebootRequestRule().EvaluateAsync(At(r,0))).Matched);
        if(kind=="enterprise")
        {
            Assert.True(r.SnmpEnterpriseSetRequestObserved);
            Assert.True((await new R966_PublicSnmpEnterpriseSetRequestRule().EvaluateAsync(At(r,0))).Matched);
        }
    }

    [Fact]
    public async Task ScopeAndDatagramCompleteness()
    {
        foreach(var r in new[]{Capture(src:"10.1.1.10"),Capture(dst:"9.9.9.9"),
            Capture(port:162),Capture(badLength:true)})
            Assert.False((await new R969_PublicSnmpUpsRebootRequestRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task ForgedAndContradictoryTelemetryDoesNotMatch()
    {
        var fake=JsonSerializer.Deserialize<TrafficRecord>(
            "{\"SnmpUpsRebootRequestObserved\":true,\"ApplicationProtocol\":\"snmp.ups.reboot.request\"}")!;
        Assert.False(fake.SnmpUpsRebootRequestObserved);
        var rule=new R969_PublicSnmpUpsRebootRequestRule();
        var label=Capture(new byte[]{1,2,3});
        label.ApplicationProtocol="snmp.ups.reboot.request";label.Info="upsRebootWithDuration.0";
        Assert.False((await rule.EvaluateAsync(At(label,0))).Matched);
        foreach(string kind in new[]{"id","tcp","tls","dns","http","port","label","enterprise"})
        {
            var r=Capture();
            switch(kind)
            {
                case "id":r.Id=Guid.Empty;break;
                case "tcp":r.IsTcp=true;break;
                case "tls":r.Sni="other.example";break;
                case "dns":r.DnsIsResponse=true;break;
                case "http":r.HttpUri="/admin";break;
                case "port":r.DestinationPort=162;break;
                case "label":r.ApplicationProtocol="UDP";break;
                case "enterprise":r.SnmpEnterpriseSetRequestObserved=true;break;
            }
            Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
        }
    }
    [Fact]
    public async Task DuplicateReverseCooldownAndPeerIsolation()
    {
        var rule=new R969_PublicSnmpUpsRebootRequestRule();
        var first=Capture();first.Info="RAW-PRIVATE-UPS-MARKER";
        var match=await rule.EvaluateAsync(At(first,100));
        Assert.True(match.Matched);
        Assert.DoesNotContain("RAW-PRIVATE-UPS-MARKER",JsonSerializer.Serialize(match.Events));
        Assert.False((await rule.EvaluateAsync(At(first,101))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Capture(),99))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),200))).Suppressed);
        Assert.True((await rule.EvaluateAsync(At(Capture(dst:"10.1.2.46"),201))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),1000))).Matched);
        Assert.True((await new R969_PublicSnmpUpsRebootRequestRule().EvaluateAsync(At(Capture(),100))).Matched);
    }
    [Fact]
    public void RegistryUniqueAndShadow()
    {
        var rules=RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count,rules.Select(r=>r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        var rule=Assert.IsType<R969_PublicSnmpUpsRebootRequestRule>(Assert.Single(rules.Where(r=>r.Descriptor.RuleId=="R969")));
        Assert.Equal(RulePrecisionMaturity.Candidate,rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow,rule.PrecisionProfile.DefaultMode);
    }
}
