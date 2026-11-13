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
public sealed class R979BacnetEventDisableQualityTests
{
    private static readonly DateTime Epoch=new(2026,11,13,0,0,0,DateTimeKind.Utc);
    private static byte[] Request(uint type=0,uint instance=1,byte priority=0,byte apdu=0)
    {
        var p=new byte[]{0x81,0x0A,0,22,1,(byte)(4|priority),apdu,5,7,15,0x0C,0,0,0,0,0x19,35,0x3E,0x82,5,0,0x3F};
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(11,4),(type<<22)|instance);
        return p;
    }
    private static TrafficRecord Capture(byte[]? data=null,string src="8.8.8.8",string dst="10.1.2.45",
        int sport=51000,int dport=47808,bool inconsistent=false)
        => TftpCaptureQualificationTests.Parse(new PacketHandler(),src,dst,sport,dport,data??Request(),inconsistent);
    private static RuleEvaluationContext At(TrafficRecord r,int s)=>new(r,Sensitivity.Balanced,Epoch.AddSeconds(s));
    [Theory]
    [InlineData(0,0,0,0,51000)]
    [InlineData(3,1,0,0,47808)]
    [InlineData(0,4194302,3,2,51000)]
    [InlineData(3,100,1,2,65535)]
    public async Task CompleteCaptureAllowedObjectAndHeaderVariants(int type,int instance,int priority,int apdu,int sport)
    {
        var r=Capture(Request((uint)type,(uint)instance,(byte)priority,(byte)apdu),sport:sport);
        Assert.True(r.BacnetEventDisableRequestObserved);
        Assert.False(r.BacnetWritePropertyRequestObserved);
        Assert.False(r.BacnetDeviceCommunicationDisableObserved);
        Assert.Equal("bacnet.event_enable.disable_all.request",r.ApplicationProtocol);
        r.Info="PRIVATE-BACNET-EVENT-FIXTURE";
        var result=await new R979_PublicBacnetEventDisableRequestRule().EvaluateAsync(At(r,0));
        Assert.True(result.Matched);
        foreach(IDetectionRule other in new IDetectionRule[]{new R485_BACnetWritePropertyRequestRule(),
            new R486_BACnetDeviceCommunicationControlRule(),new R975_PublicBacnetReinitializeDeviceRequestRule(),
            new R977_PublicBacnetObjectListReadRule()})
            Assert.False((await other.EvaluateAsync(At(r,0))).Matched);
        Assert.DoesNotContain("PRIVATE-BACNET-EVENT-FIXTURE",JsonSerializer.Serialize(result.Events));
    }
    [Theory]
    [InlineData("offnormal-enabled")]
    [InlineData("fault-enabled")]
    [InlineData("normal-enabled")]
    [InlineData("all-enabled")]
    [InlineData("nonzero-padding")]
    [InlineData("wrong-unused-bits")]
    [InlineData("wrong-bit-tag")]
    [InlineData("wrong-property")]
    [InlineData("wrong-object")]
    [InlineData("wildcard-instance")]
    [InlineData("array-index")]
    [InlineData("priority")]
    [InlineData("wrong-service")]
    [InlineData("broadcast")]
    [InlineData("forwarded")]
    [InlineData("wrong-bvlc")]
    [InlineData("length")]
    [InlineData("npdu-version")]
    [InlineData("no-reply")]
    [InlineData("routing")]
    [InlineData("network-message")]
    [InlineData("reserved-npdu")]
    [InlineData("segmented")]
    [InlineData("more-follows")]
    [InlineData("ack")]
    [InlineData("invalid-max-apdu")]
    [InlineData("invalid-max-segments")]
    [InlineData("wrong-object-tag")]
    [InlineData("wrong-property-tag")]
    [InlineData("wrong-opening")]
    [InlineData("wrong-closing")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    public async Task OtherOperationsAndMalformedFramesFailClosed(string kind)
    {
        var p=Request();
        switch(kind)
        {
            case "offnormal-enabled":p[20]=0x80;break;
            case "fault-enabled":p[20]=0x40;break;
            case "normal-enabled":p[20]=0x20;break;
            case "all-enabled":p[20]=0xE0;break;
            case "nonzero-padding":p[20]=1;break;
            case "wrong-unused-bits":p[19]=4;break;
            case "wrong-bit-tag":p[18]=0x22;break;
            case "wrong-property":p[16]=85;break;
            case "wrong-object":p=Request(8);break;
            case "wildcard-instance":p=Request(0,0x3FFFFF);break;
            case "array-index":
                p=p[..17].Concat(new byte[]{0x29,1}).Concat(p[17..]).ToArray();
                BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2,2),(ushort)p.Length);break;
            case "priority":
                p=p.Concat(new byte[]{0x49,8}).ToArray();
                BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2,2),(ushort)p.Length);break;
            case "wrong-service":p[9]=12;break;
            case "broadcast":p[1]=0x0B;break;
            case "forwarded":p[1]=4;break;
            case "wrong-bvlc":p[0]=0x82;break;
            case "length":p[3]=21;break;
            case "npdu-version":p[4]=2;break;
            case "no-reply":p[5]=0;break;
            case "routing":p[5]=0x24;break;
            case "network-message":p[5]=0x84;break;
            case "reserved-npdu":p[5]=0x44;break;
            case "segmented":p[6]=8;break;
            case "more-follows":p[6]=4;break;
            case "ack":p[6]=0x30;break;
            case "invalid-max-apdu":p[7]=6;break;
            case "invalid-max-segments":p[7]=0x85;break;
            case "wrong-object-tag":p[10]=0x1C;break;
            case "wrong-property-tag":p[15]=0x29;break;
            case "wrong-opening":p[17]=0x2E;break;
            case "wrong-closing":p[21]=0x2F;break;
            case "truncated":p=p[..^1];break;
            case "trailing":p=p.Concat(new byte[]{0}).ToArray();break;
        }
        Assert.False(BacnetEventDisableInspector.TryInspect(p));
        var r=Capture(p);
        Assert.False(r.BacnetEventDisableRequestObserved);
        Assert.False((await new R979_PublicBacnetEventDisableRequestRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task ScopeAndDatagramIntegrity()
    {
        foreach(var r in new[]{Capture(src:"10.1.1.10"),Capture(dst:"9.9.9.9"),
            Capture(dport:47809),Capture(inconsistent:true)})
            Assert.False((await new R979_PublicBacnetEventDisableRequestRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task ScalarWriteIsNotEventDisable()
    {
        var p=Request();p[16]=85;p[18]=0x22;p[19]=0;p[20]=1;
        var r=Capture(p);
        Assert.True(r.BacnetWritePropertyRequestObserved);
        Assert.False(r.BacnetEventDisableRequestObserved);
        Assert.False((await new R979_PublicBacnetEventDisableRequestRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task LabelsAndContradictoryFieldsCannotReplaceProof()
    {
        var fake=JsonSerializer.Deserialize<TrafficRecord>("{\"BacnetEventDisableRequestObserved\":true}")!;
        Assert.False(fake.BacnetEventDisableRequestObserved);
        var label=Capture(new byte[]{1,2,3});label.ApplicationProtocol="bacnet.event_enable.disable_all.request";
        var rule=new R979_PublicBacnetEventDisableRequestRule();
        Assert.False((await rule.EvaluateAsync(At(label,0))).Matched);
        foreach(string kind in new[]{"id","tcp","tls","dns","http","port","label","write","dcc","restart","directory"})
        {
            var r=Capture();
            switch(kind)
            {
                case "id":r.Id=Guid.Empty;break;
                case "tcp":r.IsTcp=true;break;
                case "tls":r.Sni="other.example";break;
                case "dns":r.DnsIsResponse=true;break;
                case "http":r.HttpUri="/admin";break;
                case "port":r.DestinationPort=47809;break;
                case "label":r.ApplicationProtocol="UDP";break;
                case "write":r.BacnetWritePropertyRequestObserved=true;break;
                case "dcc":r.BacnetDeviceCommunicationDisableObserved=true;break;
                case "restart":r.BacnetReinitializeDeviceRequestObserved=true;break;
                case "directory":r.BacnetObjectListReadObserved=true;break;
            }
            Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
        }
    }
    [Fact]
    public async Task DuplicateReverseCooldownAndPeerIsolation()
    {
        var rule=new R979_PublicBacnetEventDisableRequestRule();var first=Capture();
        Assert.True((await rule.EvaluateAsync(At(first,100))).Matched);
        Assert.False((await rule.EvaluateAsync(At(first,101))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Capture(),99))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),200))).Suppressed);
        Assert.True((await rule.EvaluateAsync(At(Capture(dst:"10.1.2.46"),201))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),1000))).Matched);
        Assert.True((await new R979_PublicBacnetEventDisableRequestRule().EvaluateAsync(At(first,100))).Matched);
    }
    [Fact]
    public void RegistryUniqueAndShadow()
    {
        var rules=RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count,rules.Select(r=>r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        var rule=Assert.IsType<R979_PublicBacnetEventDisableRequestRule>(Assert.Single(rules.Where(r=>r.Descriptor.RuleId=="R979")));
        Assert.Equal(RulePrecisionMaturity.Candidate,rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow,rule.PrecisionProfile.DefaultMode);
    }
}
