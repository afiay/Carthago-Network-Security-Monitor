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
public sealed class R972SnmpSystemFingerprintQualityTests
{
    private static readonly DateTime Epoch = new(2026,11,13,0,0,0,DateTimeKind.Utc);
    private const string Community = "private-system-community-fixture";
    private static byte[] Tlv(byte tag, params byte[][] fields)
    {
        var b=fields.SelectMany(x=>x).ToArray();
        byte[] len=b.Length<128?new[]{(byte)b.Length}:b.Length<=255?
            new[]{(byte)0x81,(byte)b.Length}:new[]{(byte)0x82,(byte)(b.Length>>8),(byte)b.Length};
        return new[]{tag}.Concat(len).Concat(b).ToArray();
    }
    private static byte[] I(params byte[] b)=>Tlv(2,b);
    private static byte[] Oid(byte obj,byte instance=0)=>new byte[]{0x2B,6,1,2,1,1,obj,instance};
    private static byte[] Binding(byte obj,byte instance=0,byte[]? value=null)
        =>Tlv(0x30,Tlv(6,Oid(obj,instance)),value??Tlv(5));
    private static byte[] Message(byte[][]? bindings=null,byte version=1,byte pdu=0xA0,
        byte error=0,byte index=0,byte[]? id=null)
        =>Tlv(0x30,I(version),Tlv(4,Encoding.ASCII.GetBytes(Community)),
            Tlv(pdu,id??I(7),I(error),I(index),Tlv(0x30,bindings??new[]{Binding(1),Binding(2),Binding(5)})));
    private static TrafficRecord Capture(byte[]? data=null,string src="8.8.8.8",string dst="10.1.2.45",
        int sport=51000,int dport=161,bool inconsistent=false)
        =>TftpCaptureQualificationTests.Parse(new PacketHandler(),src,dst,sport,dport,data??Message(),inconsistent);
    private static RuleEvaluationContext At(TrafficRecord r,int s)=>new(r,Sensitivity.Balanced,Epoch.AddSeconds(s));

    [Theory]
    [InlineData(0,1,2,5)]
    [InlineData(1,1,5,2)]
    [InlineData(1,2,1,5)]
    [InlineData(1,2,5,1)]
    [InlineData(1,5,1,2)]
    [InlineData(1,5,2,1)]
    public async Task CompleteCaptureAndAllPermutations(int version,int a,int b,int c)
    {
        var r=Capture(Message(new[]{Binding((byte)a),Binding((byte)b),Binding((byte)c)},(byte)version));
        Assert.True(r.SnmpSystemFingerprintGetObserved);
        Assert.False(r.SnmpEnterpriseSetRequestObserved);
        Assert.False(r.SnmpUpsRebootRequestObserved);
        Assert.False(r.SnmpHighDemandGetBulkObserved);
        r.Info="PRIVATE-SYSTEM-FIXTURE-MARKER";
        var result=await new R972_PublicSnmpSystemFingerprintGetRule().EvaluateAsync(At(r,0));
        Assert.True(result.Matched);
        foreach(IDetectionRule other in new IDetectionRule[]{new R771_PublicSnmpQueryBurstToPrivateHostRule(),
            new R966_PublicSnmpEnterpriseSetRequestRule(),new R969_PublicSnmpUpsRebootRequestRule(),
            new R971_PublicSnmpHighDemandGetBulkRule()})
            Assert.False((await other.EvaluateAsync(At(r,0))).Matched);
        Assert.DoesNotContain("PRIVATE-SYSTEM-FIXTURE-MARKER",JsonSerializer.Serialize(result.Events));
        Assert.DoesNotContain(Community,JsonSerializer.Serialize(new { Record=r,result.Events }));
    }

    [Theory]
    [InlineData("single")]
    [InlineData("two")]
    [InlineData("empty")]
    [InlineData("duplicate")]
    [InlineData("extra")]
    [InlineData("uptime")]
    [InlineData("wrong-instance")]
    [InlineData("wrong-prefix")]
    [InlineData("missing-instance")]
    [InlineData("malformed-oid")]
    [InlineData("value")]
    [InlineData("nonempty-null")]
    [InlineData("getnext")]
    [InlineData("getbulk")]
    [InlineData("set")]
    [InlineData("response")]
    [InlineData("v3")]
    [InlineData("error")]
    [InlineData("index")]
    [InlineData("noncanonical-id")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    public async Task OrdinaryOrMalformedRequestFailsClosed(string kind)
    {
        var a=Binding(1);var b=Binding(2);var c=Binding(5);
        byte[] p=kind switch
        {
            "single"=>Message(new[]{a}), "two"=>Message(new[]{a,b}), "empty"=>Message(Array.Empty<byte[]>()),
            "duplicate"=>Message(new[]{a,b,b}), "extra"=>Message(new[]{a,b,c,Binding(3)}),
            "uptime"=>Message(new[]{a,b,Binding(3)}), "wrong-instance"=>Message(new[]{a,b,Binding(5,1)}),
            "wrong-prefix"=>Message(new[]{a,b,Tlv(0x30,Tlv(6,new byte[]{0x2B,6,1,4,1,1,5,0}),Tlv(5))}),
            "missing-instance"=>Message(new[]{a,b,Tlv(0x30,Tlv(6,Oid(5)[..^1]),Tlv(5))}),
            "malformed-oid"=>Message(new[]{a,b,Tlv(0x30,Tlv(6,new byte[]{0x2B,6,1,2,1,1,5,0x80}),Tlv(5))}),
            "value"=>Message(new[]{a,b,Binding(5,value:I(1))}),
            "nonempty-null"=>Message(new[]{a,b,Binding(5,value:Tlv(5,new byte[]{1}))}),
            "getnext"=>Message(pdu:0xA1), "getbulk"=>Message(pdu:0xA5,index:64),
            "set"=>Message(pdu:0xA3), "response"=>Message(pdu:0xA2), "v3"=>Message(version:3),
            "error"=>Message(error:1), "index"=>Message(index:1), "noncanonical-id"=>Message(id:I(0,7)),
            "truncated"=>Message()[..^1], _=>Message().Concat(new byte[]{0}).ToArray()
        };
        Assert.False(SnmpEnterpriseSetInspector.TryInspectSystemFingerprintGet(p));
        var r=Capture(p);
        Assert.False(r.SnmpSystemFingerprintGetObserved);
        Assert.False((await new R972_PublicSnmpSystemFingerprintGetRule().EvaluateAsync(At(r,0))).Matched);
        if(kind=="getbulk")
        {
            Assert.True(r.SnmpHighDemandGetBulkObserved);
            Assert.True((await new R971_PublicSnmpHighDemandGetBulkRule().EvaluateAsync(At(r,0))).Matched);
        }
    }

    [Fact]
    public async Task ScopeAndDatagramIntegrity()
    {
        foreach(var r in new[]{Capture(src:"10.1.1.10"),Capture(dst:"9.9.9.9"),
            Capture(sport:161),Capture(dport:162),Capture(inconsistent:true)})
            Assert.False((await new R972_PublicSnmpSystemFingerprintGetRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task LabelsAndContradictoryFieldsCannotReplaceProof()
    {
        var fake=JsonSerializer.Deserialize<TrafficRecord>("{\"SnmpSystemFingerprintGetObserved\":true}")!;
        Assert.False(fake.SnmpSystemFingerprintGetObserved);
        var label=Capture(new byte[]{1,2,3});label.ApplicationProtocol="snmp.get.system_fingerprint.request";
        var rule=new R972_PublicSnmpSystemFingerprintGetRule();
        Assert.False((await rule.EvaluateAsync(At(label,0))).Matched);
        foreach(string kind in new[]{"id","tcp","tls","dns","http","port","label","enterprise","ups","bulk"})
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
                case "bulk":r.SnmpHighDemandGetBulkObserved=true;break;
            }
            Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
        }
    }
    [Fact]
    public async Task DuplicateReverseCooldownAndPeerIsolation()
    {
        var rule=new R972_PublicSnmpSystemFingerprintGetRule();var first=Capture();
        Assert.True((await rule.EvaluateAsync(At(first,100))).Matched);
        Assert.False((await rule.EvaluateAsync(At(first,101))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Capture(),99))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),200))).Suppressed);
        Assert.True((await rule.EvaluateAsync(At(Capture(dst:"10.1.2.46"),201))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),1000))).Matched);
        Assert.True((await new R972_PublicSnmpSystemFingerprintGetRule().EvaluateAsync(At(first,100))).Matched);
    }
    [Fact]
    public void RegistryUniqueAndShadow()
    {
        var rules=RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count,rules.Select(r=>r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        var rule=Assert.IsType<R972_PublicSnmpSystemFingerprintGetRule>(Assert.Single(rules.Where(r=>r.Descriptor.RuleId=="R972")));
        Assert.Equal(RulePrecisionMaturity.Candidate,rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow,rule.PrecisionProfile.DefaultMode);
    }
}
