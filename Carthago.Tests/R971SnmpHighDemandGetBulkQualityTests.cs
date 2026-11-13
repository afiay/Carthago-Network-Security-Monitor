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
public sealed class R971SnmpHighDemandGetBulkQualityTests
{
    private static readonly DateTime Epoch = new(2026,11,13,0,0,0,DateTimeKind.Utc);
    private const string Community = "private-bulk-community-fixture";
    private static byte[] Tlv(byte tag, params byte[][] fields)
    {
        var b=fields.SelectMany(x=>x).ToArray();
        byte[] len=b.Length<128?new[]{(byte)b.Length}:b.Length<=255?
            new[]{(byte)0x81,(byte)b.Length}:new[]{(byte)0x82,(byte)(b.Length>>8),(byte)b.Length};
        return new[]{tag}.Concat(len).Concat(b).ToArray();
    }
    private static byte[] I(params byte[] b)=>Tlv(2,b);
    private static byte[] Num(int n)=> n<=127 ? I((byte)n) : I((byte)(n>>8),(byte)n);
    private static byte[] Message(int repetitions=64,int count=1,byte version=1,byte pdu=0xA5,
        byte[]? repeat=null,byte[]? oid=null,byte[]? value=null,byte nonRepeaters=0)
    {
        var bindings=Enumerable.Range(0,count).Select(n=>Tlv(0x30,
            Tlv(6,oid??new byte[]{0x2B,6,1,2,1,2,2,1,(byte)(n+1)}),value??Tlv(5))).ToArray();
        return Tlv(0x30,I(version),Tlv(4,Encoding.ASCII.GetBytes(Community)),
            Tlv(pdu,I(7),I(nonRepeaters),repeat??Num(repetitions),Tlv(0x30,bindings)));
    }
    private static TrafficRecord Capture(byte[]? data=null,string src="8.8.8.8",string dst="10.1.2.45",
        int sport=51000,int dport=161,bool inconsistent=false)
        =>TftpCaptureQualificationTests.Parse(new PacketHandler(),src,dst,sport,dport,data??Message(),inconsistent);
    private static RuleEvaluationContext At(TrafficRecord r,int s)=>new(r,Sensitivity.Balanced,Epoch.AddSeconds(s));

    [Theory]
    [InlineData(64,1)]
    [InlineData(127,1)]
    [InlineData(128,2)]
    [InlineData(1024,8)]
    public async Task CompleteCaptureNumericAndCountBoundaries(int repetitions,int count)
    {
        var r=Capture(Message(repetitions,count));
        Assert.True(r.SnmpHighDemandGetBulkObserved);
        Assert.False(r.SnmpEnterpriseSetRequestObserved);
        Assert.False(r.SnmpUpsRebootRequestObserved);
        Assert.Equal("snmp.getbulk.high_demand.request",r.ApplicationProtocol);
        r.Info="PRIVATE-BULK-FIXTURE-MARKER";
        var result=await new R971_PublicSnmpHighDemandGetBulkRule().EvaluateAsync(At(r,0));
        Assert.True(result.Matched);
        Assert.False((await new R771_PublicSnmpQueryBurstToPrivateHostRule().EvaluateAsync(At(r,0))).Matched);
        Assert.False((await new R966_PublicSnmpEnterpriseSetRequestRule().EvaluateAsync(At(r,0))).Matched);
        Assert.False((await new R969_PublicSnmpUpsRebootRequestRule().EvaluateAsync(At(r,0))).Matched);
        Assert.DoesNotContain("PRIVATE-BULK-FIXTURE-MARKER",JsonSerializer.Serialize(result.Events));
        Assert.DoesNotContain(Community,JsonSerializer.Serialize(new { Record=r,result.Events }));
    }
    [Theory]
    [InlineData("zero")]
    [InlineData("ordinary")]
    [InlineData("below")]
    [InlineData("above")]
    [InlineData("nonrepeaters")]
    [InlineData("negative")]
    [InlineData("noncanonical")]
    [InlineData("overflow")]
    [InlineData("empty-integer")]
    [InlineData("v1")]
    [InlineData("v3")]
    [InlineData("get")]
    [InlineData("getnext")]
    [InlineData("set")]
    [InlineData("response")]
    [InlineData("empty-list")]
    [InlineData("too-many")]
    [InlineData("bad-oid")]
    [InlineData("oid-overflow")]
    [InlineData("value")]
    [InlineData("nonempty-null")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    public async Task OrdinaryOrMalformedRequestFailsClosed(string kind)
    {
        byte[] p=kind switch
        {
            "zero"=>Message(0), "ordinary"=>Message(10), "below"=>Message(63), "above"=>Message(1025),
            "nonrepeaters"=>Message(nonRepeaters:1),
            "negative"=>Message(repeat:I(0xFF)), "noncanonical"=>Message(repeat:I(0,64)),
            "overflow"=>Message(repeat:I(0,0x80,0,0,0)), "empty-integer"=>Message(repeat:I()),
            "v1"=>Message(version:0), "v3"=>Message(version:3),
            "get"=>Message(pdu:0xA0), "getnext"=>Message(pdu:0xA1),
            "set"=>Message(pdu:0xA3), "response"=>Message(pdu:0xA2),
            "empty-list"=>Message(count:0), "too-many"=>Message(count:9),
            "bad-oid"=>Message(oid:new byte[]{0x2B,0x80}),
            "oid-overflow"=>Message(oid:new byte[]{0x2B,0x90,0x80,0x80,0x80,0x80,0}),
            "value"=>Message(value:I(1)), "nonempty-null"=>Message(value:Tlv(5,new byte[]{1})),
            "truncated"=>Message()[..^1], _=>Message().Concat(new byte[]{0}).ToArray()
        };
        Assert.False(SnmpEnterpriseSetInspector.TryInspectHighDemandBulk(p));
        var r=Capture(p);
        Assert.False(r.SnmpHighDemandGetBulkObserved);
        Assert.False((await new R971_PublicSnmpHighDemandGetBulkRule().EvaluateAsync(At(r,0))).Matched);
    }

    [Fact]
    public async Task WrongScopeAndInconsistentDatagramCannotMatch()
    {
        foreach(var r in new[]{Capture(src:"10.1.1.10"),Capture(dst:"9.9.9.9"),
            Capture(sport:161),Capture(dport:162),Capture(inconsistent:true)})
            Assert.False((await new R971_PublicSnmpHighDemandGetBulkRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task LabelsAndContradictoryFieldsCannotReplaceProof()
    {
        var fake=JsonSerializer.Deserialize<TrafficRecord>("{\"SnmpHighDemandGetBulkObserved\":true}")!;
        Assert.False(fake.SnmpHighDemandGetBulkObserved);
        var label=Capture(new byte[]{1,2,3});label.ApplicationProtocol="snmp.getbulk.high_demand.request";
        var rule=new R971_PublicSnmpHighDemandGetBulkRule();
        Assert.False((await rule.EvaluateAsync(At(label,0))).Matched);
        foreach(string kind in new[]{"id","tcp","tls","dns","http","port","label","enterprise","ups"})
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
                case "ups":r.SnmpUpsRebootRequestObserved=true;break;
            }
            Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
        }
    }
    [Fact]
    public async Task DuplicateReverseCooldownAndPeerIsolation()
    {
        var rule=new R971_PublicSnmpHighDemandGetBulkRule();var first=Capture();
        Assert.True((await rule.EvaluateAsync(At(first,100))).Matched);
        Assert.False((await rule.EvaluateAsync(At(first,101))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Capture(),99))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),200))).Suppressed);
        Assert.True((await rule.EvaluateAsync(At(Capture(dst:"10.1.2.46"),201))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),1000))).Matched);
        Assert.True((await new R971_PublicSnmpHighDemandGetBulkRule().EvaluateAsync(At(first,100))).Matched);
    }
    [Fact]
    public void RegistryUniqueAndShadow()
    {
        var rules=RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count,rules.Select(r=>r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        var rule=Assert.IsType<R971_PublicSnmpHighDemandGetBulkRule>(Assert.Single(rules.Where(r=>r.Descriptor.RuleId=="R971")));
        Assert.Equal(RulePrecisionMaturity.Candidate,rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow,rule.PrecisionProfile.DefaultMode);
    }
}
