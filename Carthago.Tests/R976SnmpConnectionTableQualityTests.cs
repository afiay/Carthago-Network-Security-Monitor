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
public sealed class R976SnmpConnectionTableQualityTests
{
    private static readonly DateTime Epoch=new(2026,11,13,0,0,0,DateTimeKind.Utc);
    private const string Community="private-connection-table-fixture";
    private static byte[] Tlv(byte tag,params byte[][] fields)
    {
        var b=fields.SelectMany(x=>x).ToArray();
        byte[] len=b.Length<128?new[]{(byte)b.Length}:b.Length<=255?
            new[]{(byte)0x81,(byte)b.Length}:new[]{(byte)0x82,(byte)(b.Length>>8),(byte)b.Length};
        return new[]{tag}.Concat(len).Concat(b).ToArray();
    }
    private static byte[] I(params byte[] b)=>Tlv(2,b);
    private static byte[] Tcp()=>new byte[]{0x2B,6,1,2,1,6,13};
    private static byte[] Udp()=>new byte[]{0x2B,6,1,2,1,7,5};
    private static byte[] Binding(byte[] oid,byte[]? value=null)=>Tlv(0x30,Tlv(6,oid),value??Tlv(5));
    private static byte[] Message(byte[][]? bindings=null,byte version=1,byte pdu=0xA1,
        byte error=0,byte index=0,byte[]? id=null)
        =>Tlv(0x30,I(version),Tlv(4,Encoding.ASCII.GetBytes(Community)),
            Tlv(pdu,id??I(7),I(error),I(index),Tlv(0x30,bindings??new[]{Binding(Tcp()),Binding(Udp())})));
    private static TrafficRecord Capture(byte[]? data=null,string src="8.8.8.8",string dst="10.1.2.45",
        int sport=51000,int dport=161,bool inconsistent=false)
        =>TftpCaptureQualificationTests.Parse(new PacketHandler(),src,dst,sport,dport,data??Message(),inconsistent);
    private static RuleEvaluationContext At(TrafficRecord r,int s)=>new(r,Sensitivity.Balanced,Epoch.AddSeconds(s));

    [Theory]
    [InlineData(0,false)]
    [InlineData(0,true)]
    [InlineData(1,false)]
    [InlineData(1,true)]
    public async Task CompleteCaptureVersionsAndBothOrders(int version,bool reverse)
    {
        var r=Capture(Message(reverse?new[]{Binding(Udp()),Binding(Tcp())}:new[]{Binding(Tcp()),Binding(Udp())},(byte)version));
        Assert.True(r.SnmpConnectionTableGetNextObserved);
        Assert.Equal("snmp.getnext.connection_tables.request",r.ApplicationProtocol);
        r.Info="PRIVATE-CONNECTION-TABLE-MARKER";
        var result=await new R976_PublicSnmpConnectionTableGetNextRule().EvaluateAsync(At(r,0));
        Assert.True(result.Matched);
        foreach(IDetectionRule other in new IDetectionRule[]{new R771_PublicSnmpQueryBurstToPrivateHostRule(),
            new R966_PublicSnmpEnterpriseSetRequestRule(),new R969_PublicSnmpUpsRebootRequestRule(),
            new R971_PublicSnmpHighDemandGetBulkRule(),new R972_PublicSnmpSystemFingerprintGetRule()})
            Assert.False((await other.EvaluateAsync(At(r,0))).Matched);
        Assert.DoesNotContain("PRIVATE-CONNECTION-TABLE-MARKER",JsonSerializer.Serialize(result.Events));
        Assert.DoesNotContain(Community,JsonSerializer.Serialize(new{Record=r,result.Events}));
    }
    [Theory]
    [InlineData("tcp-only")]
    [InlineData("udp-only")]
    [InlineData("empty")]
    [InlineData("duplicate-tcp")]
    [InlineData("duplicate-udp")]
    [InlineData("extra")]
    [InlineData("adjacent")]
    [InlineData("instance")]
    [InlineData("wrong-prefix")]
    [InlineData("malformed-oid")]
    [InlineData("value")]
    [InlineData("nonempty-null")]
    [InlineData("get")]
    [InlineData("getbulk")]
    [InlineData("set")]
    [InlineData("response")]
    [InlineData("v3")]
    [InlineData("error")]
    [InlineData("index")]
    [InlineData("noncanonical-id")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    public async Task BenignAndMalformedRequestsFailClosed(string kind)
    {
        var a=Binding(Tcp());var b=Binding(Udp());
        byte[] p=kind switch
        {
            "tcp-only"=>Message(new[]{a}), "udp-only"=>Message(new[]{b}), "empty"=>Message(Array.Empty<byte[]>()),
            "duplicate-tcp"=>Message(new[]{a,a}), "duplicate-udp"=>Message(new[]{b,b}),
            "extra"=>Message(new[]{a,b,a}), "adjacent"=>Message(new[]{a,Binding(new byte[]{0x2B,6,1,2,1,7,4})}),
            "instance"=>Message(new[]{a,Binding(Udp().Concat(new byte[]{0}).ToArray())}),
            "wrong-prefix"=>Message(new[]{a,Binding(new byte[]{0x2B,6,1,4,1,7,5})}),
            "malformed-oid"=>Message(new[]{a,Binding(new byte[]{0x2B,6,1,2,1,7,0x80})}),
            "value"=>Message(new[]{a,Binding(Udp(),I(1))}),
            "nonempty-null"=>Message(new[]{a,Binding(Udp(),Tlv(5,new byte[]{1}))}),
            "get"=>Message(pdu:0xA0), "getbulk"=>Message(pdu:0xA5,index:64),
            "set"=>Message(pdu:0xA3), "response"=>Message(pdu:0xA2), "v3"=>Message(version:3),
            "error"=>Message(error:1), "index"=>Message(index:1), "noncanonical-id"=>Message(id:I(0,7)),
            "truncated"=>Message()[..^1], _=>Message().Concat(new byte[]{0}).ToArray()
        };
        Assert.False(SnmpEnterpriseSetInspector.TryInspectConnectionTableGetNext(p));
        var r=Capture(p);
        Assert.False(r.SnmpConnectionTableGetNextObserved);
        Assert.False((await new R976_PublicSnmpConnectionTableGetNextRule().EvaluateAsync(At(r,0))).Matched);
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
            Assert.False((await new R976_PublicSnmpConnectionTableGetNextRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task LabelsAndContradictoryFieldsCannotReplaceProof()
    {
        var fake=JsonSerializer.Deserialize<TrafficRecord>("{\"SnmpConnectionTableGetNextObserved\":true}")!;
        Assert.False(fake.SnmpConnectionTableGetNextObserved);
        var rule=new R976_PublicSnmpConnectionTableGetNextRule();
        var label=Capture(new byte[]{1,2,3});label.ApplicationProtocol="snmp.getnext.connection_tables.request";
        Assert.False((await rule.EvaluateAsync(At(label,0))).Matched);
        foreach(string kind in new[]{"id","tcp","tls","dns","http","port","label","enterprise","ups","bulk","fingerprint"})
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
                case "fingerprint":r.SnmpSystemFingerprintGetObserved=true;break;
            }
            Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
        }
    }
    [Fact]
    public async Task DuplicateReverseCooldownAndPeerIsolation()
    {
        var rule=new R976_PublicSnmpConnectionTableGetNextRule();var first=Capture();
        Assert.True((await rule.EvaluateAsync(At(first,100))).Matched);
        Assert.False((await rule.EvaluateAsync(At(first,101))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Capture(),99))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),200))).Suppressed);
        Assert.True((await rule.EvaluateAsync(At(Capture(dst:"10.1.2.46"),201))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),1000))).Matched);
        Assert.True((await new R976_PublicSnmpConnectionTableGetNextRule().EvaluateAsync(At(first,100))).Matched);
    }
    [Fact]
    public void RegistryUniqueAndShadow()
    {
        var rules=RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count,rules.Select(r=>r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        var rule=Assert.IsType<R976_PublicSnmpConnectionTableGetNextRule>(Assert.Single(rules.Where(r=>r.Descriptor.RuleId=="R976")));
        Assert.Equal(RulePrecisionMaturity.Candidate,rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow,rule.PrecisionProfile.DefaultMode);
    }
}
