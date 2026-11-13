// SPDX-License-Identifier: MIT
using Carthago.Services;
using PacketDotNet;
using Xunit;

namespace Carthago.Tests;

public sealed class PortableTransportIntegrationTests
{
    [Fact]
    public void ExistingHandlerPreservesTcpHeaderSummary()
    {
        byte[] frame=new byte[43];
        frame[0]=0x45; frame[3]=43; frame[8]=64; frame[9]=6;
        frame[12]=192; frame[14]=2; frame[15]=1;
        frame[16]=198; frame[17]=51; frame[18]=100; frame[19]=2;
        frame[20]=0xc3; frame[21]=0x50; frame[22]=1; frame[23]=0xbb;
        frame[32]=0x50; frame[33]=0x02;
        var record=new PacketHandler().ParseFrame(frame,(LinkLayers)101);
        Assert.NotNull(record); Assert.True(record!.IsTcp);
        Assert.Equal(50000,record.SourcePort); Assert.Equal(443,record.DestinationPort);
        Assert.Equal((ushort)2,record.TcpFlags); Assert.Equal(3,record.L4Len);
        frame[32]=0x40;
        Assert.Null(new PacketHandler().ParseFrame(frame,(LinkLayers)101));
    }

    [Fact]
    public void ExistingHandlerPreservesIcmpSummary()
    {
        byte[] frame=new byte[28]; frame[0]=0x45; frame[3]=28; frame[8]=64; frame[9]=1;
        frame[20]=8;
        var record=new PacketHandler().ParseFrame(frame,(LinkLayers)101);
        Assert.NotNull(record); Assert.Equal("ICMP",record!.Protocol);
        Assert.Equal((ushort)0x0800,record.IcmpTypeCode); Assert.Equal(8,record.L4Len);
        Assert.Null(record.SourcePort); Assert.Null(record.DestinationPort);
    }
}
