// SPDX-License-Identifier: MIT
using Carthago.Services;
using PacketDotNet;
using Xunit;

namespace Carthago.Tests;
public sealed class PortablePacketAdapterTests
{
    [Fact]
    public void WindowsRawFrameAdapterPreservesCoreTelemetry()
    {
        byte[] wire={0x45,0,0,28,0,0,0,0,64,17,0,0,192,0,2,1,198,51,100,2,
            0xc3,0x50,0xd4,0x31,0,8,0,0};
        var host=new PacketHandler().ParseFrame(wire,(LinkLayers)101);
        var core=new PortablePacketProcessor(()=>DateTime.UtcNow,
            (port,proto)=>PortServiceResolver.GetServiceName(port,proto)).ParseFrame(wire,101);
        Assert.NotNull(host);Assert.NotNull(core);
        Assert.Equal(host!.Source,core!.Source);Assert.Equal(host.Destination,core.Destination);
        Assert.Equal(host.SourcePort,core.SourcePort);Assert.Equal(host.DestinationPort,core.DestinationPort);
        Assert.Equal(host.Protocol,core.Protocol);Assert.Equal(host.Length,core.Length);
        Assert.Equal(host.ApplicationService,core.ApplicationService);
    }
}
