// SPDX-License-Identifier: MIT
using Carthago.Services;
using PacketDotNet;
using Xunit;

namespace Carthago.Tests;

public sealed class PortableFrameHeaderIntegrationTests
{
    [Theory]
    [InlineData(101,0)]
    [InlineData(1,14)]
    [InlineData(113,16)]
    [InlineData(276,20)]
    public void ExistingPacketHandlerConsumesSharedHeaders(int linkType,int offset)
    {
        byte[] ip={0x45,0,0,28,0,0,0,0,64,17,0,0,192,0,2,1,198,51,100,2,0xc3,0x50,0,53,0,8,0,0};
        var frame=new byte[offset+ip.Length];
        ip.CopyTo(frame,offset);
        if(linkType==1)frame[12]=8;
        if(linkType==113)frame[14]=8;
        if(linkType==276)frame[0]=8;
        var record=new PacketHandler().ParseFrame(frame,(LinkLayers)linkType);
        Assert.NotNull(record);
        Assert.Equal("192.0.2.1",record!.Source);
        Assert.Equal("198.51.100.2",record.Destination);
        Assert.True(record.IsUdp);
        Assert.Equal(50000,record.SourcePort);
        Assert.Equal(53,record.DestinationPort);
        Assert.Equal(0,record.L4Len);
        Assert.Equal(28,record.Length);
    }
}
