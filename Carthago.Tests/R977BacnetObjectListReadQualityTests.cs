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
public sealed class R977BacnetObjectListReadQualityTests
{
    private static readonly DateTime Epoch=new(2026,11,13,0,0,0,DateTimeKind.Utc);
    private static byte[] Request(uint instance=1,byte priority=0,byte apdu=0,byte invoke=7)
    {
        var p=new byte[]{0x81,0x0A,0,17,1,(byte)(4|priority),apdu,5,invoke,12,0x0C,0,0,0,0,0x19,76};
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(11,4),(8u<<22)|instance);
        return p;
    }
    private static TrafficRecord Capture(byte[]? data=null,string src="8.8.8.8",string dst="10.1.2.45",
        int sport=51000,int dport=47808,bool inconsistent=false)
        => TftpCaptureQualificationTests.Parse(new PacketHandler(),src,dst,sport,dport,data??Request(),inconsistent);
    private static RuleEvaluationContext At(TrafficRecord r,int s)=>new(r,Sensitivity.Balanced,Epoch.AddSeconds(s));
    [Theory]
    [InlineData(0,0,0,51000)]
    [InlineData(1,0,0,47808)]
    [InlineData(4194302,3,2,51000)]
    [InlineData(100,1,2,65535)]
    public async Task CompleteCaptureAndAllowedHeaderVariants(int instance,int priority,int apdu,int sport)
    {
        var r=Capture(Request((uint)instance,(byte)priority,(byte)apdu),sport:sport);
        Assert.True(r.BacnetObjectListReadObserved);
        Assert.False(r.BacnetReinitializeDeviceRequestObserved);
        Assert.False(r.BacnetWritePropertyRequestObserved);
        Assert.False(r.BacnetDeviceCommunicationDisableObserved);
        Assert.Equal("bacnet.device.object_list.read",r.ApplicationProtocol);
        r.Info="PRIVATE-BACNET-DIRECTORY-FIXTURE";
        var result=await new R977_PublicBacnetObjectListReadRule().EvaluateAsync(At(r,0));
        Assert.True(result.Matched);
        foreach(IDetectionRule other in new IDetectionRule[]{new R485_BACnetWritePropertyRequestRule(),
            new R486_BACnetDeviceCommunicationControlRule(),new R975_PublicBacnetReinitializeDeviceRequestRule()})
            Assert.False((await other.EvaluateAsync(At(r,0))).Matched);
        Assert.DoesNotContain("PRIVATE-BACNET-DIRECTORY-FIXTURE",JsonSerializer.Serialize(result.Events));
    }
    [Theory]
    [InlineData("present-value")]
    [InlineData("object-name")]
    [InlineData("object-type")]
    [InlineData("wildcard-instance")]
    [InlineData("array-length")]
    [InlineData("array-element")]
    [InlineData("write")]
    [InlineData("dcc")]
    [InlineData("restart")]
    [InlineData("read-multiple")]
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
    [InlineData("truncated")]
    [InlineData("trailing")]
    public async Task OtherOperationsAndMalformedFramesFailClosed(string kind)
    {
        var p=Request();
        switch(kind)
        {
            case "present-value":p[16]=85;break;
            case "object-name":p[16]=77;break;
            case "object-type":BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(11,4),1);break;
            case "wildcard-instance":p=Request(0x3FFFFF);break;
            case "array-length":case "array-element":
                p=p.Concat(new byte[]{0x29,(byte)(kind=="array-length"?0:1)}).ToArray();
                BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2,2),(ushort)p.Length);break;
            case "write":p[9]=15;break;
            case "dcc":p[9]=17;break;
            case "restart":p[9]=20;break;
            case "read-multiple":p[9]=14;break;
            case "broadcast":p[1]=0x0B;break;
            case "forwarded":p[1]=4;break;
            case "wrong-bvlc":p[0]=0x82;break;
            case "length":p[3]=16;break;
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
            case "truncated":p=p[..^1];break;
            case "trailing":p=p.Concat(new byte[]{0}).ToArray();break;
        }
        Assert.False(BacnetObjectListReadInspector.TryInspect(p));
        var r=Capture(p);
        Assert.False(r.BacnetObjectListReadObserved);
        Assert.False((await new R977_PublicBacnetObjectListReadRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task ScopeAndDatagramIntegrity()
    {
        foreach(var r in new[]{Capture(src:"10.1.1.10"),Capture(dst:"9.9.9.9"),
            Capture(dport:47809),Capture(inconsistent:true)})
            Assert.False((await new R977_PublicBacnetObjectListReadRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task RestartIsNotDirectoryRead()
    {
        var r=Capture(new byte[]{0x81,0x0A,0,12,1,4,0,5,7,20,0x09,0});
        Assert.True(r.BacnetReinitializeDeviceRequestObserved);
        Assert.False(r.BacnetObjectListReadObserved);
        Assert.False((await new R977_PublicBacnetObjectListReadRule().EvaluateAsync(At(r,0))).Matched);
        Assert.True((await new R975_PublicBacnetReinitializeDeviceRequestRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task LabelsAndContradictoryFieldsCannotReplaceProof()
    {
        var fake=JsonSerializer.Deserialize<TrafficRecord>("{\"BacnetObjectListReadObserved\":true}")!;
        Assert.False(fake.BacnetObjectListReadObserved);
        var label=Capture(new byte[]{1,2,3});label.ApplicationProtocol="bacnet.device.object_list.read";
        var rule=new R977_PublicBacnetObjectListReadRule();
        Assert.False((await rule.EvaluateAsync(At(label,0))).Matched);
        foreach(string kind in new[]{"id","tcp","tls","dns","http","port","label","write","dcc","restart"})
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
            }
            Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
        }
    }
    [Fact]
    public async Task DuplicateReverseCooldownAndPeerIsolation()
    {
        var rule=new R977_PublicBacnetObjectListReadRule();var first=Capture();
        Assert.True((await rule.EvaluateAsync(At(first,100))).Matched);
        Assert.False((await rule.EvaluateAsync(At(first,101))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Capture(),99))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),200))).Suppressed);
        Assert.True((await rule.EvaluateAsync(At(Capture(dst:"10.1.2.46"),201))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),1000))).Matched);
        Assert.True((await new R977_PublicBacnetObjectListReadRule().EvaluateAsync(At(first,100))).Matched);
    }
    [Fact]
    public void RegistryUniqueAndShadow()
    {
        var rules=RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count,rules.Select(r=>r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        var rule=Assert.IsType<R977_PublicBacnetObjectListReadRule>(Assert.Single(rules.Where(r=>r.Descriptor.RuleId=="R977")));
        Assert.Equal(RulePrecisionMaturity.Candidate,rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow,rule.PrecisionProfile.DefaultMode);
    }
}
