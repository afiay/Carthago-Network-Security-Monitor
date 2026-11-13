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
public sealed class R975BacnetReinitializeDeviceQualityTests
{
    private static readonly DateTime Epoch=new(2026,11,13,0,0,0,DateTimeKind.Utc);
    private static byte[] Request(byte state=0,byte priority=0,byte apdu=0,byte invoke=7)
        => new byte[]{0x81,0x0A,0,12,1,(byte)(4|priority),apdu,5,invoke,20,0x09,state};
    private static TrafficRecord Capture(byte[]? data=null,string src="8.8.8.8",string dst="10.1.2.45",
        int sport=51000,int dport=47808,bool inconsistent=false)
        => TftpCaptureQualificationTests.Parse(new PacketHandler(),src,dst,sport,dport,data??Request(),inconsistent);
    private static RuleEvaluationContext At(TrafficRecord r,int s)=>new(r,Sensitivity.Balanced,Epoch.AddSeconds(s));

    [Theory]
    [InlineData(0,0,0,51000)]
    [InlineData(1,0,0,47808)]
    [InlineData(0,3,2,51000)]
    [InlineData(1,1,2,65535)]
    public async Task CompleteCaptureColdWarmAndAllowedHeaderVariants(int state,int priority,int apdu,int sport)
    {
        var r=Capture(Request((byte)state,(byte)priority,(byte)apdu),sport:sport);
        Assert.True(r.BacnetReinitializeDeviceRequestObserved);
        Assert.False(r.BacnetWritePropertyRequestObserved);
        Assert.False(r.BacnetDeviceCommunicationDisableObserved);
        Assert.Equal("bacnet.reinitialize_device.request",r.ApplicationProtocol);
        r.Info="PRIVATE-BACNET-RESTART-FIXTURE";
        var result=await new R975_PublicBacnetReinitializeDeviceRequestRule().EvaluateAsync(At(r,0));
        Assert.True(result.Matched);
        Assert.False((await new R485_BACnetWritePropertyRequestRule().EvaluateAsync(At(r,0))).Matched);
        Assert.False((await new R486_BACnetDeviceCommunicationControlRule().EvaluateAsync(At(r,0))).Matched);
        Assert.DoesNotContain("PRIVATE-BACNET-RESTART-FIXTURE",JsonSerializer.Serialize(result.Events));
    }
    [Theory]
    [InlineData("start-backup")]
    [InlineData("end-backup")]
    [InlineData("start-restore")]
    [InlineData("end-restore")]
    [InlineData("abort-restore")]
    [InlineData("activate")]
    [InlineData("unknown-state")]
    [InlineData("write")]
    [InlineData("dcc")]
    [InlineData("read")]
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
    [InlineData("wrong-tag")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    [InlineData("password")]
    public async Task OtherOperationsAndMalformedFramesFailClosed(string kind)
    {
        var p=Request();
        switch(kind)
        {
            case "start-backup":p[11]=2;break;
            case "end-backup":p[11]=3;break;
            case "start-restore":p[11]=4;break;
            case "end-restore":p[11]=5;break;
            case "abort-restore":p[11]=6;break;
            case "activate":p[11]=7;break;
            case "unknown-state":p[11]=255;break;
            case "write":p[9]=15;break;
            case "dcc":p[9]=17;break;
            case "read":p[9]=12;break;
            case "broadcast":p[1]=0x0B;break;
            case "forwarded":p[1]=4;break;
            case "wrong-bvlc":p[0]=0x82;break;
            case "length":p[3]=11;break;
            case "npdu-version":p[4]=2;break;
            case "no-reply":p[5]=0;break;
            case "routing":p[5]=0x24;break;
            case "network-message":p[5]=0x84;break;
            case "reserved-npdu":p[5]=0x44;break;
            case "segmented":p[6]=8;break;
            case "more-follows":p[6]=4;break;
            case "ack":p[6]=0x20;break;
            case "invalid-max-apdu":p[7]=6;break;
            case "invalid-max-segments":p[7]=0x85;break;
            case "wrong-tag":p[10]=0x19;break;
            case "truncated":p=p[..^1];break;
            case "trailing":p=p.Concat(new byte[]{0}).ToArray();break;
            case "password":
                p=p.Concat(new byte[]{0x1A,0,65}).ToArray();
                BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2,2),(ushort)p.Length);break;
        }
        Assert.False(BacnetReinitializeDeviceInspector.TryInspect(p));
        var r=Capture(p);
        Assert.False(r.BacnetReinitializeDeviceRequestObserved);
        Assert.False((await new R975_PublicBacnetReinitializeDeviceRequestRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task ScopeAndDatagramIntegrity()
    {
        foreach(var r in new[]{Capture(src:"10.1.1.10"),Capture(dst:"9.9.9.9"),
            Capture(dport:47809),Capture(inconsistent:true)})
            Assert.False((await new R975_PublicBacnetReinitializeDeviceRequestRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task DccDisableIsNotRestart()
    {
        var p=Request();p[9]=17;p[10]=0x19;p[11]=1;
        var r=Capture(p);
        Assert.True(r.BacnetDeviceCommunicationDisableObserved);
        Assert.False(r.BacnetReinitializeDeviceRequestObserved);
        Assert.False((await new R975_PublicBacnetReinitializeDeviceRequestRule().EvaluateAsync(At(r,0))).Matched);
        Assert.True((await new R486_BACnetDeviceCommunicationControlRule().EvaluateAsync(At(r,0))).Matched);
    }
    [Fact]
    public async Task LabelsAndContradictoryFieldsCannotReplaceProof()
    {
        var fake=JsonSerializer.Deserialize<TrafficRecord>("{\"BacnetReinitializeDeviceRequestObserved\":true}")!;
        Assert.False(fake.BacnetReinitializeDeviceRequestObserved);
        var label=Capture(new byte[]{1,2,3});label.ApplicationProtocol="bacnet.reinitialize_device.request";
        var rule=new R975_PublicBacnetReinitializeDeviceRequestRule();
        Assert.False((await rule.EvaluateAsync(At(label,0))).Matched);
        foreach(string kind in new[]{"id","tcp","tls","dns","http","port","label","write","dcc"})
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
            }
            Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
        }
    }
    [Fact]
    public async Task DuplicateReverseCooldownAndPeerIsolation()
    {
        var rule=new R975_PublicBacnetReinitializeDeviceRequestRule();var first=Capture();
        Assert.True((await rule.EvaluateAsync(At(first,100))).Matched);
        Assert.False((await rule.EvaluateAsync(At(first,101))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Capture(),99))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),200))).Suppressed);
        Assert.True((await rule.EvaluateAsync(At(Capture(dst:"10.1.2.46"),201))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),1000))).Matched);
        Assert.True((await new R975_PublicBacnetReinitializeDeviceRequestRule().EvaluateAsync(At(first,100))).Matched);
    }
    [Fact]
    public void RegistryUniqueAndShadow()
    {
        var rules=RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count,rules.Select(r=>r.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        var rule=Assert.IsType<R975_PublicBacnetReinitializeDeviceRequestRule>(Assert.Single(rules.Where(r=>r.Descriptor.RuleId=="R975")));
        Assert.Equal(RulePrecisionMaturity.Candidate,rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow,rule.PrecisionProfile.DefaultMode);
    }
}
