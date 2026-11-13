// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortablePacketHelperTests
{
    private static readonly DateTime Epoch=new(2026,1,1,0,0,0,DateTimeKind.Utc);

    [Fact]
    public void HelpersHaveOnePortableOwner()
    {
        var core=typeof(OtProtocolLight).Assembly;
        Assert.Equal("Carthago.Core",core.GetName().Name);
        foreach(var type in new[]{typeof(NetworkBatch226230Wire),typeof(NetworkBatch231235Wire),
            typeof(NetworkBatch246250Wire),typeof(DnsAObservationInspector),typeof(EtherNetIpRegisterSessionInspector),
            typeof(FinsControllerStopInspector),typeof(FinsDataMemoryClearInspector),typeof(FinsNodeNegotiationInspector),
            typeof(TlsIdentityEnrichment)})
            Assert.Same(core,type.Assembly);
        Assert.DoesNotContain(core.GetReferencedAssemblies(),a=>a.Name is "Carthago" or "PresentationFramework" or "PresentationCore" or "WindowsBase");
    }

    [Fact]
    public void MqttPublishRetainsTopicAndRetainBitOnlyWithMatchingEnvelope()
    {
        byte[] wire={0x31,5,0,3,0x63,0x6d,0x64};
        Assert.True(NetworkBatch226230Wire.Mqtt(wire,51000,1883,out var op,out var topic,out var retain));
        Assert.Equal("mqtt.publish",op);Assert.Equal("cmd",topic);Assert.True(retain);
        Assert.True(NetworkBatch226230Wire.IsControlTopic(topic));
        Assert.False(NetworkBatch226230Wire.IsControlTopic("device/commanding"));
        Assert.False(NetworkBatch226230Wire.Mqtt(wire,51000,1884,out _,out _,out _));
        Assert.False(NetworkBatch226230Wire.Mqtt(wire[..^1],51000,1883,out _,out _,out _));
    }

    [Fact]
    public void CipListIdentityRequiresExactEnvelope()
    {
        var wire=new byte[24];wire[0]=0x63;
        Assert.True(NetworkBatch226230Wire.CipListIdentity(wire,51000,44818));
        Assert.False(NetworkBatch226230Wire.CipListIdentity(wire,51000,44819));
        Assert.False(NetworkBatch226230Wire.CipListIdentity(wire[..^1],51000,44818));
    }

    [Fact]
    public void CoapDiscoveryRequiresExactPathAndPort()
    {
        var wire=new byte[]{0x40,1,0,1,0xbb}.Concat(".well-known"u8.ToArray())
            .Concat(new byte[]{4}).Concat("core"u8.ToArray()).ToArray();
        Assert.True(NetworkBatch231235Wire.CoapDiscovery(wire,51000,5683));
        Assert.False(NetworkBatch231235Wire.CoapDiscovery(wire,51000,5684));
        Assert.False(NetworkBatch231235Wire.CoapDiscovery(wire[..^1],51000,5683));
    }

    [Fact]
    public void WsDiscoveryProhibitsDtdAndRequiresOnvifProbe()
    {
        const string xml="<d:Probe xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" xmlns:n=\"http://www.onvif.org/ver10/network/wsdl\"><d:Types>n:NetworkVideoTransmitter</d:Types></d:Probe>";
        Assert.True(NetworkBatch231235Wire.WsDiscoveryProbe(Encoding.UTF8.GetBytes(xml),51000,3702));
        Assert.False(NetworkBatch231235Wire.WsDiscoveryProbe(Encoding.UTF8.GetBytes("<!DOCTYPE d:Probe>"+xml),51000,3702));
        Assert.False(NetworkBatch231235Wire.WsDiscoveryProbe(Encoding.UTF8.GetBytes(xml.Replace("NetworkVideoTransmitter","Other")),51000,3702));
    }

    [Theory]
    [InlineData("STOR fixture\r\n","ftp.stor")]
    [InlineData("APPE fixture\r\n","ftp.appe")]
    public void FtpUploadClassifiesOperationWithoutPath(string request,string expected)
    {
        var wire=Encoding.ASCII.GetBytes(request);
        Assert.True(NetworkBatch246250Wire.FtpUpload(wire,51000,21,out var op));
        Assert.Equal(expected,op);
        Assert.False(NetworkBatch246250Wire.FtpUpload(wire,21,51000,out _));
        Assert.False(NetworkBatch246250Wire.FtpUpload(wire[..^1],51000,21,out _));
    }

    [Fact]
    public void OtModbusDirectionDoesNotPromoteResponseToWrite()
    {
        byte[] wire={0,1,0,0,0,6,1,6,0,42,0,99};
        Assert.True(OtProtocolLight.TryIdentifyTcp(wire,51000,502,out var request));
        Assert.Equal("modbus.write",request);
        Assert.True(OtProtocolLight.TryIdentifyTcp(wire,502,51000,out var response));
        Assert.Equal("modbus",response);
        Assert.False(OtProtocolLight.TryIdentifyTcp(wire,51000,503,out _));
    }

    [Fact]
    public void DnsSingleARequiresExactQuestionAndAnswerOwner()
    {
        byte[] q={0x12,0x34,1,0,0,1,0,0,0,0,0,0,1,0x61,4,0x74,0x65,0x73,0x74,0,0,1,0,1};
        Assert.True(DnsAObservationInspector.TryInspect(q,out var query));
        Assert.Equal("a.test",query.Name);Assert.False(query.IsResponse);
        var reply=q.Concat(new byte[]{0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,192,0,2,1}).ToArray();
        reply[2]=0x81;reply[3]=0x80;reply[7]=1;
        Assert.True(DnsAObservationInspector.TryInspect(reply,out var answer));
        Assert.Equal("192.0.2.1",answer.Address);Assert.Equal(60,answer.Ttl);
        Assert.False(DnsAObservationInspector.TryInspect(reply[..^1],out _));
        reply[7]=2;Assert.False(DnsAObservationInspector.TryInspect(reply,out _));
    }

    [Fact]
    public void EtherNetIpSessionRequiresMatchingContextAndTime()
    {
        var request=new byte[28];request[0]=0x65;request[2]=4;request[12]=7;request[24]=1;
        Assert.True(EtherNetIpRegisterSessionInspector.TryRequest(request,Epoch,out var pending));
        var reply=(byte[])request.Clone();reply[4]=1;
        Assert.True(EtherNetIpRegisterSessionInspector.IsMatchingResponse(reply,pending,Epoch.AddSeconds(30)));
        Assert.False(EtherNetIpRegisterSessionInspector.IsMatchingResponse(reply,pending,Epoch.AddSeconds(31)));
        reply[12]=8;Assert.False(EtherNetIpRegisterSessionInspector.IsMatchingResponse(reply,pending,Epoch));
    }

    [Fact]
    public void FinsStopRequiresExactCommandAndDistinctNodes()
    {
        byte[] wire={0x80,0,2,0,1,0,0,2,0,0,4,2};
        Assert.True(FinsControllerStopInspector.TryInspect(wire));
        Assert.False(FinsControllerStopInspector.TryInspect(wire[..^1]));
        wire[7]=1;Assert.False(FinsControllerStopInspector.TryInspect(wire));
    }

    [Fact]
    public void FinsMemoryClearRequiresSixteenZeroWords()
    {
        var wire=new byte[50];wire[0]=0x80;wire[2]=2;wire[4]=1;wire[7]=2;
        wire[10]=1;wire[11]=2;wire[12]=0x82;wire[17]=16;
        Assert.True(FinsDataMemoryClearInspector.TryInspect(wire));
        wire[^1]=1;Assert.False(FinsDataMemoryClearInspector.TryInspect(wire));
    }

    [Fact]
    public void FinsNodeNegotiationRequiresMatchingNodeAndTime()
    {
        var request=new byte[20];"FINS"u8.CopyTo(request);request[7]=12;request[19]=5;
        Assert.True(FinsNodeNegotiationInspector.TryRequest(request,Epoch,out var pending));
        var reply=new byte[24];"FINS"u8.CopyTo(reply);reply[7]=16;reply[11]=1;reply[19]=5;reply[23]=6;
        Assert.True(FinsNodeNegotiationInspector.IsMatchingResponse(reply,pending,Epoch.AddSeconds(30)));
        Assert.False(FinsNodeNegotiationInspector.IsMatchingResponse(reply,pending,Epoch.AddSeconds(31)));
        reply[19]=7;Assert.False(FinsNodeNegotiationInspector.IsMatchingResponse(reply,pending,Epoch));
    }

    [Fact]
    public void TlsServerHelloUsesSelectedVersionNotLegacyVersion()
    {
        var body=new List<byte>{3,3};body.AddRange(new byte[32]);
        body.AddRange(new byte[]{0,0x13,1,0,0,6,0,43,0,2,3,4});
        var hs=new byte[]{2,0,0,(byte)body.Count}.Concat(body).ToArray();
        var wire=new byte[]{22,3,3,0,(byte)hs.Length}.Concat(hs).ToArray();
        Assert.True(TlsIdentityEnrichment.TryReadServerHello(wire,out var result));
        Assert.Equal("TLS1.3",result.Version);Assert.Null(result.Alpn);
        Assert.False(TlsIdentityEnrichment.TryReadServerHello(wire[..^1],out _));
    }

    [Fact]
    public void TlsCertificateDerSanAndWildcardMatching()
    {
        using var key=RSA.Create(2048);
        var req=new CertificateRequest("CN=fixture.test",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        var san=new SubjectAlternativeNameBuilder();san.AddDnsName("*.example.test");san.AddDnsName("fixture.test");
        req.CertificateExtensions.Add(san.Build());
        var now=DateTimeOffset.UtcNow;
        using var cert=req.CreateSelfSigned(now.AddDays(-1),now.AddDays(1));
        var record=new TrafficRecord();
        TlsIdentityEnrichment.ApplyCertificate(record,cert);
        Assert.Equal("DnsSanObserved",record.TlsCertificateNameStatus);
        Assert.Equal("*.example.test; fixture.test",record.TlsCertificateDnsNames);
        Assert.Equal("WithinValidityPeriod",record.TlsCertificateValidityStatus);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(cert.RawData)).ToLowerInvariant(),record.TlsCertificateSha256);
        Assert.Equal("MatchesDnsSan",TlsIdentityEnrichment.MatchName("a.example.test",record.TlsCertificateDnsNames,record.TlsCertificateNameStatus));
        Assert.Equal("DoesNotMatchDnsSan",TlsIdentityEnrichment.MatchName("a.b.example.test",record.TlsCertificateDnsNames,record.TlsCertificateNameStatus));
    }
}
