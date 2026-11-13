// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Linq;
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
public sealed class R985FinsControllerStopQualityTests
{
    private static readonly DateTime Epoch=new(2026,11,13,0,0,0,DateTimeKind.Utc);
    private static byte[] Request(byte source=7,byte destination=1,byte sid=0)
        => new byte[]{0x80,0,2,0,destination,0,0,source,0,sid,4,2};
    private static TrafficRecord Capture(byte[]? data=null,string src="8.8.8.8",string dst="10.1.2.45",
        int sport=9600,int dport=9600,bool inconsistent=false)
        => TftpCaptureQualificationTests.Parse(new PacketHandler(),src,dst,sport,dport,data??Request(),inconsistent);
    private static RuleEvaluationContext At(TrafficRecord r,int s)=>new(r,Sensitivity.Balanced,Epoch.AddSeconds(s));

    [Theory]
    [InlineData(1,254,0)]
    [InlineData(254,1,255)]
    [InlineData(7,8,42)]
    public async Task CompleteCaptureNodeAndSidBoundaries(int source,int destination,int sid)
    {
        var r=Capture(Request((byte)source,(byte)destination,(byte)sid));
        Assert.True(r.FinsControllerStopObserved);
        Assert.False(r.FinsDataMemoryClearObserved);
        Assert.False(r.FinsNodeNegotiationObserved);
        Assert.Equal("fins.udp.controller_stop.request",r.ApplicationProtocol);
        r.Info="PRIVATE-FINS-STOP-FIXTURE";
        var result=await new R985_PublicFinsControllerStopRequestRule().EvaluateAsync(At(r,0));
        Assert.True(result.Matched);
        Assert.DoesNotContain("PRIVATE-FINS-STOP-FIXTURE",JsonSerializer.Serialize(result.Events));
        Assert.False((await new R984_PublicFinsDataMemoryClearRule().EvaluateAsync(At(r,0))).Matched);
        Assert.False((await new R983_PrivateFinsNodeNegotiationToPublicClientRule().EvaluateAsync(At(r,0))).Matched);
    }

    [Theory]
    [InlineData("run")]
    [InlineData("read")]
    [InlineData("write")]
    [InlineData("other-command")]
    [InlineData("response")]
    [InlineData("no-response-request")]
    [InlineData("reserved")]
    [InlineData("gateway-count")]
    [InlineData("destination-network")]
    [InlineData("source-network")]
    [InlineData("destination-unit")]
    [InlineData("source-unit")]
    [InlineData("destination-zero")]
    [InlineData("destination-broadcast")]
    [InlineData("source-zero")]
    [InlineData("source-broadcast")]
    [InlineData("same-node")]
    [InlineData("parameters")]
    [InlineData("truncated")]
    [InlineData("coalesced")]
    public async Task OtherOperationsAndMalformedFramesFailClosed(string kind)
    {
        var p=Request();
        switch(kind)
        {
            case "run":p[11]=1;p=p.Concat(new byte[]{0xFF,0xFF,4}).ToArray();break;
            case "read":p[10]=1;p[11]=1;break;
            case "write":p[10]=1;p[11]=2;break;
            case "other-command":p[11]=3;break;
            case "response":p[0]=0xC0;p=p.Concat(new byte[]{0,0}).ToArray();break;
            case "no-response-request":p[0]=0x81;break;
            case "reserved":p[1]=1;break;
            case "gateway-count":p[2]=3;break;
            case "destination-network":p[3]=1;break;
            case "source-network":p[6]=1;break;
            case "destination-unit":p[5]=1;break;
            case "source-unit":p[8]=1;break;
            case "destination-zero":p[4]=0;break;
            case "destination-broadcast":p[4]=255;break;
            case "source-zero":p[7]=0;break;
            case "source-broadcast":p[7]=255;break;
            case "same-node":p[7]=p[4];break;
            case "parameters":p=p.Concat(new byte[]{0}).ToArray();break;
            case "truncated":p=p[..^1];break;
            case "coalesced":p=p.Concat(Request()).ToArray();break;
        }
        Assert.False(FinsControllerStopInspector.TryInspect(p));
        var r=Capture(p);
        Assert.False(r.FinsControllerStopObserved);
        Assert.False((await new R985_PublicFinsControllerStopRequestRule().EvaluateAsync(At(r,0))).Matched);
    }

    [Fact]
    public async Task CompleteMemoryWriteIsNotStop()
    {
        var p=new byte[50];
        new byte[]{0x80,0,2,0,1,0,0,7,0,0,1,2,0x82}.CopyTo(p,0);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(16,2),16);
        var r=Capture(p);
        Assert.True(r.FinsDataMemoryClearObserved);
        Assert.False(r.FinsControllerStopObserved);
        Assert.True((await new R984_PublicFinsDataMemoryClearRule().EvaluateAsync(At(r,0))).Matched);
        Assert.False((await new R985_PublicFinsControllerStopRequestRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task ScopeAndDatagramIntegrity()
    {
        foreach(var r in new[]{Capture(src:"10.1.1.10"),Capture(dst:"9.9.9.9"),
            Capture(sport:9601),Capture(dport:9601),Capture(inconsistent:true)})
            Assert.False((await new R985_PublicFinsControllerStopRequestRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task LabelsAndContradictoryFieldsCannotReplaceProof()
    {
        var fake=JsonSerializer.Deserialize<TrafficRecord>("{\"FinsControllerStopObserved\":true}")!;
        Assert.False(fake.FinsControllerStopObserved);
        var label=Capture(new byte[]{1,2,3});label.ApplicationProtocol="fins.udp.controller_stop.request";
        var rule=new R985_PublicFinsControllerStopRequestRule();
        Assert.False((await rule.EvaluateAsync(At(label,0))).Matched);
        foreach(string kind in new[]{"id","tcp","tls","dns","http","port","label","negotiation","write"})
        {
            var r=Capture();
            switch(kind)
            {
                case "id":r.Id=Guid.Empty;break;
                case "tcp":r.IsTcp=true;break;
                case "tls":r.Sni="other.example";break;
                case "dns":r.DnsIsResponse=true;break;
                case "http":r.HttpUri="/admin";break;
                case "port":r.DestinationPort=9601;break;
                case "label":r.ApplicationProtocol="UDP";break;
                case "negotiation":r.FinsNodeNegotiationObserved=true;break;
                case "write":r.FinsDataMemoryClearObserved=true;break;
            }
            Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
        }
    }
    [Fact]
    public async Task DuplicateReverseCooldownAndPeerIsolation()
    {
        var rule=new R985_PublicFinsControllerStopRequestRule();var first=Capture();
        Assert.True((await rule.EvaluateAsync(At(first,100))).Matched);
        Assert.False((await rule.EvaluateAsync(At(first,101))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Capture(),99))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),200))).Suppressed);
        Assert.True((await rule.EvaluateAsync(At(Capture(dst:"10.1.2.46"),201))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),1000))).Matched);
        Assert.True((await new R985_PublicFinsControllerStopRequestRule().EvaluateAsync(At(first,100))).Matched);
    }
    [Fact]
    public void RegistryUniqueAndShadow()
    {
        var rules=RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count,rules.Select(r=>r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        var rule=Assert.IsType<R985_PublicFinsControllerStopRequestRule>(Assert.Single(rules.Where(r=>r.Descriptor.RuleId=="R985")));
        Assert.Equal(RulePrecisionMaturity.Candidate,rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow,rule.PrecisionProfile.DefaultMode);
    }
}
