// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using Carthago.Services;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableFrameHeaderTests
{
    private static byte[] Ipv4() => new byte[]
    {
        0x45,0,0,28,0,0,0,0,64,17,0,0,192,0,2,1,198,51,100,2,
        0xc3,0x50,0,53,0,8,0,0
    };

    private static byte[] Wrap(byte[] ip, int linkType)
    {
        int size = linkType switch { 1 => 14, 0 => 4, 113 => 16, 276 => 20, _ => 0 };
        var frame = new byte[size + ip.Length];
        ip.CopyTo(frame, size);
        if (linkType == 1) { frame[0] = 0xaa; frame[6] = 0xbb; frame[12] = 8; }
        if (linkType == 0) frame[0] = 2;
        if (linkType == 113) frame[14] = 8;
        if (linkType == 276) frame[0] = 8;
        return frame;
    }

    [Theory]
    [InlineData(1,14)]
    [InlineData(0,4)]
    [InlineData(12,0)]
    [InlineData(101,0)]
    [InlineData(228,0)]
    [InlineData(113,16)]
    [InlineData(276,20)]
    public void SupportedLinkFormatsDecodeSameIpv4Header(int linkType, int offset)
    {
        var frame = Wrap(Ipv4(), linkType);
        var link = PortableFrameHeaders.ParseLink(frame, linkType);
        Assert.NotNull(link);
        Assert.Equal(offset, link.Value.Offset);
        Assert.Equal((ushort)0x0800, link.Value.EtherType);
        var ip = PortableFrameHeaders.ParseIp(frame, link.Value);
        Assert.NotNull(ip);
        Assert.True(ip.Value.IsIPv4);
        Assert.Equal("192.0.2.1", ip.Value.Source);
        Assert.Equal("198.51.100.2", ip.Value.Destination);
        Assert.Equal((byte)17, ip.Value.TransportProtocol);
        Assert.Equal(offset+20, ip.Value.TransportOffset);
        Assert.Equal(8, ip.Value.PayloadLength);
        Assert.True(ip.Value.Complete);
        Assert.Equal(28, ip.Value.PacketLength);
        if (linkType == 1) Assert.Equal("BB:00:00:00:00:00", link.Value.MacSource);
    }

    [Fact]
    public void StackedVlanAndDepthLimit()
    {
        var ip = Ipv4();
        var frame = new byte[22 + ip.Length];
        frame[12]=0x81; frame[16]=0x88; frame[17]=0xa8; frame[20]=8;
        ip.CopyTo(frame,22);
        var link = PortableFrameHeaders.ParseLink(frame,1);
        Assert.NotNull(link);
        Assert.Equal(22,link.Value.Offset);
        Assert.NotNull(PortableFrameHeaders.ParseIp(frame,link.Value));
        var deep = new byte[14+9*4+ip.Length];
        for(int i=0;i<9;i++) deep[12+i*4]=0x81;
        deep[12+9*4]=8;
        ip.CopyTo(deep,14+9*4);
        Assert.Null(PortableFrameHeaders.ParseLink(deep,1));
        Assert.Null(PortableFrameHeaders.ParseLink(frame.AsSpan(0,17),1));
    }

    [Fact]
    public void TruncatedIpv4DistinguishesHeaderAndPacketCompleteness()
    {
        var wire=Ipv4();
        var link=PortableFrameHeaders.ParseLink(wire,101)!.Value;
        for(int n=0;n<20;n++) Assert.Null(PortableFrameHeaders.ParseIp(wire.AsSpan(0,n),link));
        var partial=PortableFrameHeaders.ParseIp(wire.AsSpan(0,24),link);
        Assert.NotNull(partial);
        Assert.False(partial.Value.Complete);
        Assert.Equal(4,partial.Value.PayloadLength);
        Assert.Equal(24,partial.Value.End);
        wire[6]=0x20;
        Assert.Null(PortableFrameHeaders.ParseIp(wire,link));
    }

    [Fact]
    public void Ipv6ExtensionAndFragmentBounds()
    {
        var wire=new byte[56];
        wire[0]=0x60; wire[5]=16; wire[6]=0; wire[7]=64;
        wire[8]=0x20; wire[9]=1; wire[23]=1; wire[24]=0x20; wire[25]=1; wire[39]=2;
        wire[40]=17; wire[41]=0;
        var link=PortableFrameHeaders.ParseLink(wire,229)!.Value;
        var ip=PortableFrameHeaders.ParseIp(wire,link);
        Assert.NotNull(ip);
        Assert.False(ip.Value.IsIPv4);
        Assert.Equal(48,ip.Value.TransportOffset);
        Assert.Equal(8,ip.Value.PayloadLength);
        wire[6]=44; wire[42]=0; wire[43]=1;
        Assert.Null(PortableFrameHeaders.ParseIp(wire,link));
        wire[43]=0;
        Assert.NotNull(PortableFrameHeaders.ParseIp(wire,link));
        wire[6]=0; wire[41]=3;
        Assert.Null(PortableFrameHeaders.ParseIp(wire,link));
    }

    [Fact]
    public void UnsupportedAndEmptyFramesFailClosed()
    {
        Assert.Null(PortableFrameHeaders.ParseLink(Array.Empty<byte>(),101));
        Assert.Null(PortableFrameHeaders.ParseLink(Ipv4(),999));
        Assert.Null(PortableFrameHeaders.ParseLink(new byte[13],1));
        Assert.Equal("Carthago.Core",typeof(PortableFrameHeaders).Assembly.GetName().Name);
    }
}
