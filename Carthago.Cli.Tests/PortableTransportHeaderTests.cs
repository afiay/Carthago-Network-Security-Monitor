// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using Carthago.Services;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableTransportHeaderTests
{
    private static byte[] Frame(byte protocol, int length)
    {
        var frame = new byte[20 + length];
        frame[0] = 0x45; frame[8] = 64; frame[9] = protocol;
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(2,2),(ushort)frame.Length);
        return frame;
    }

    private static PortableTransportHeaders.TransportHeader? Parse(byte[] frame)
    {
        var link = PortableFrameHeaders.ParseLink(frame,101);
        if (link is null) return null;
        var ip = PortableFrameHeaders.ParseIp(frame,link.Value);
        return ip is null ? null : PortableTransportHeaders.Parse(frame,ip.Value);
    }

    [Fact]
    public void TcpOptionsFlagsSequenceAndPayload()
    {
        var frame=Frame(6,27);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(20,2),50000);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(22,2),443);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(24,4),uint.MaxValue);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(28,4),42);
        frame[32]=0x61; frame[33]=0x12; frame[44]=1; frame[45]=2; frame[46]=3;
        var result=Parse(frame);
        Assert.NotNull(result);
        var h=result.Value;
        Assert.True(h.IsTcp); Assert.False(h.IsUdp);
        Assert.Equal("TCP",h.Protocol);
        Assert.Equal(50000,h.SourcePort); Assert.Equal(443,h.DestinationPort);
        Assert.Equal(uint.MaxValue,h.Sequence); Assert.Equal(42u,h.Acknowledgment);
        Assert.Equal((ushort)0x112,h.TcpFlags); Assert.True(h.Syn); Assert.True(h.Ack);
        Assert.Equal(44,h.PayloadOffset); Assert.Equal(3,h.PayloadCount); Assert.Equal(3,h.PayloadLength);
        Assert.Equal(new byte[]{1,2,3},frame.AsSpan(h.PayloadOffset,h.PayloadCount).ToArray());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(7)]
    [InlineData(15)]
    public void InvalidTcpDataOffsetFailsClosed(int words)
    {
        var frame=Frame(6,24); frame[32]=(byte)(words<<4);
        Assert.Null(Parse(frame));
    }

    [Fact]
    public void TcpHeaderTruncationAndPartialCaptureStayDistinct()
    {
        var frame=Frame(6,24); frame[32]=0x50;
        for(int n=20;n<40;n++) Assert.Null(Parse(frame[..n]));
        var partial=frame[..42];
        var link=PortableFrameHeaders.ParseLink(partial,101)!.Value;
        var ip=PortableFrameHeaders.ParseIp(partial,link)!.Value;
        Assert.False(ip.Complete);
        var h=PortableTransportHeaders.Parse(partial,ip);
        Assert.NotNull(h); Assert.Equal(2,h.Value.PayloadCount);
    }

    [Theory]
    [InlineData(8,0)]
    [InlineData(10,2)]
    [InlineData(12,4)]
    public void UdpDeclaredLengthBoundsPayloadIncludingTrailingIpBytes(int declared,int expected)
    {
        var frame=Frame(17,12);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(20,2),50000);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(22,2),53);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(24,2),(ushort)declared);
        var h=Parse(frame);
        Assert.NotNull(h); Assert.True(h.Value.IsUdp); Assert.False(h.Value.IsTcp);
        Assert.Equal(28,h.Value.PayloadOffset); Assert.Equal(expected,h.Value.PayloadCount);
        Assert.Equal(expected,h.Value.PayloadLength); Assert.Null(h.Value.TcpFlags);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(7)]
    [InlineData(13)]
    [InlineData(65535)]
    public void InvalidUdpLengthFailsClosed(int declared)
    {
        var frame=Frame(17,12);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(24,2),(ushort)declared);
        Assert.Null(Parse(frame));
    }

    [Fact]
    public void TruncatedUdpDatagramCannotProduceTransportRecord()
    {
        var frame=Frame(17,12); frame[25]=12;
        for(int n=20;n<frame.Length;n++) Assert.Null(Parse(frame[..n]));
    }

    [Theory]
    [InlineData(1,"ICMP",8,0)]
    [InlineData(58,"ICMPv6",128,0)]
    public void IcmpPreservesTypeCodeAndEmptyApplicationPayload(int protocol,string label,int type,int code)
    {
        byte[] frame;
        int offset;
        if(protocol==58)
        {
            frame=new byte[48]; frame[0]=0x60; frame[5]=8; frame[6]=58; frame[7]=64; offset=40;
        }
        else { frame=Frame(1,8); offset=20; }
        frame[offset]=(byte)type; frame[offset+1]=(byte)code;
        var h=Parse(frame);
        Assert.NotNull(h); Assert.Equal(label,h.Value.Protocol);
        Assert.Equal((ushort)((type<<8)|code),h.Value.IcmpTypeCode);
        Assert.Equal(8,h.Value.PayloadLength); Assert.Equal(0,h.Value.PayloadCount);
        Assert.Null(h.Value.SourcePort); Assert.Null(h.Value.DestinationPort);
        Assert.Null(Parse(frame[..(offset+1)]));
    }

    [Fact]
    public void UnsupportedTransportAndInvalidIpBoundsFailClosed()
    {
        Assert.Null(Parse(Frame(99,8)));
        var frame=Frame(17,8);
        var link=PortableFrameHeaders.ParseLink(frame,101)!.Value;
        var ip=PortableFrameHeaders.ParseIp(frame,link)!.Value;
        Assert.Null(PortableTransportHeaders.Parse(frame,ip with { End=frame.Length+1 }));
        Assert.Null(PortableTransportHeaders.Parse(frame,ip with { TransportOffset=-1 }));
        Assert.Null(PortableTransportHeaders.Parse(frame,ip with { PayloadLength=9 }));
    }
}
