// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using Carthago.Services;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortablePacketProcessorTests
{
    private static readonly DateTime Epoch=new(2026,1,1,12,34,56,DateTimeKind.Utc);

    private static byte[] Udp(byte[] payload,int sport=51000,int dport=53,bool reverse=false)
    {
        var wire=new byte[28+payload.Length];
        wire[0]=0x45;wire[8]=64;wire[9]=17;
        byte[] client={192,0,2,1},server={198,51,100,2};
        (reverse?server:client).CopyTo(wire,12);
        (reverse?client:server).CopyTo(wire,16);
        BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(2),(ushort)wire.Length);
        BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(20),(ushort)sport);
        BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(22),(ushort)dport);
        BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(24),(ushort)(8+payload.Length));
        payload.CopyTo(wire,28);
        return wire;
    }

    [Fact]
    public void PortableProcessorHasNoWindowsOrNativeCaptureReferences()
    {
        var core=typeof(PortablePacketProcessor).Assembly;
        Assert.Equal("Carthago.Core",core.GetName().Name);
        Assert.Same(core,typeof(EtherNetIpIdentityResetInspector).Assembly);
        Assert.DoesNotContain(core.GetReferencedAssemblies(),a=>a.Name is "Carthago" or
            "SharpPcap" or "PacketDotNet" or "PresentationFramework" or "PresentationCore" or "WindowsBase");
    }

    [Theory]
    [InlineData(101,0)]
    [InlineData(1,14)]
    [InlineData(113,16)]
    [InlineData(276,20)]
    public void RawFrameProducesSharedTrafficRecordAndDnsEvidence(int link,int offset)
    {
        byte[] query={0x12,0x34,1,0,0,1,0,0,0,0,0,0,1,0x61,4,0x74,0x65,0x73,0x74,0,0,1,0,1};
        var ip=Udp(query);var wire=new byte[offset+ip.Length];ip.CopyTo(wire,offset);
        if(link==1)wire[12]=8;
        if(link==113)wire[14]=8;
        if(link==276)wire[0]=8;
        var processor=new PortablePacketProcessor(()=>Epoch,(port,proto)=>port==53?"DNS":"Unknown");
        var rec=processor.ParseFrame(wire,link);
        Assert.NotNull(rec);
        Assert.Equal("192.0.2.1",rec!.Source);Assert.Equal("198.51.100.2",rec.Destination);
        Assert.Equal(53,rec.DestinationPort);Assert.True(rec.IsUdp);
        Assert.Equal("a.test",rec.DnsQname);Assert.True(rec.DnsValidatedAQuestion);
        Assert.Equal("12:34:56",rec.Timestamp);
        Assert.Null(processor.ParseFrame(wire[..^1],link));
    }

    [Fact]
    public void ServiceResolutionIsExplicitAndUsesDestinationThenSource()
    {
        var seen=new List<int>();
        var processor=new PortablePacketProcessor(()=>Epoch,(port,proto)=>
        {seen.Add(port);return port==51000?"fixture":"Unknown";});
        var rec=processor.ParseFrame(Udp(Array.Empty<byte>(),51000,54321),101);
        Assert.NotNull(rec);Assert.Equal("fixture",rec!.ApplicationService);
        Assert.Equal(new[]{54321,51000},seen);
        var noResolver=new PortablePacketProcessor(()=>Epoch);
        Assert.Equal("Unknown",noResolver.ParseFrame(Udp(Array.Empty<byte>(),51000,54321),101)!.ApplicationService);
    }

    [Fact]
    public void IndependentProcessorsDoNotShareTftpCorrelation()
    {
        var now=Epoch;
        var a=new PortablePacketProcessor(()=>now);var b=new PortablePacketProcessor(()=>now);
        byte[] request={0,1,0x66,0,0x6f,0x63,0x74,0x65,0x74,0};
        byte[] response={0,3,0,1,0x41};
        var req=a.ParseFrame(Udp(request,51000,69),101);
        Assert.NotNull(req);Assert.Equal((byte)1,req!.TftpInitialRequestOpcode);
        now=Epoch.AddSeconds(1);
        var unrelated=b.ParseFrame(Udp(response,52000,51000,true),101);
        Assert.NotNull(unrelated);Assert.Null(unrelated!.TftpInitialReplyOpcode);
        var matched=a.ParseFrame(Udp(response,52000,51000,true),101);
        Assert.NotNull(matched);Assert.Equal((byte)3,matched!.TftpInitialReplyOpcode);
        Assert.Equal(req.Id,matched.TftpRequestCorrelationId);
    }

    [Fact]
    public void MalformedAndUnsupportedFramesFailClosed()
    {
        var p=new PortablePacketProcessor(()=>Epoch);
        Assert.Null(p.ParseFrame(Array.Empty<byte>(),101));
        Assert.Null(p.ParseFrame(Udp(Array.Empty<byte>()),999));
        var malformed=Udp(Array.Empty<byte>());malformed[25]=9;
        Assert.Null(p.ParseFrame(malformed,101));
    }
}
