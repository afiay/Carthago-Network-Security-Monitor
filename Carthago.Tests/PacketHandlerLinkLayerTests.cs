using System.Net;
using System.Net.NetworkInformation;
using Carthago.Services;
using PacketDotNet;

namespace Carthago.Tests;

public sealed class PacketHandlerLinkLayerTests
{
    [Fact]
    public void ParseFrame_DecodesRawIpv4WithoutEthernetHeader()
    {
        var handler = new PacketHandler();
        var packet = BuildIpv4UdpPacket();

        var record = handler.ParseFrame(packet, (LinkLayers)12);

        Assert.NotNull(record);
        Assert.Equal("10.0.0.1", record.Source);
        Assert.Equal("10.0.0.2", record.Destination);
        Assert.Equal(53000, record.SourcePort);
        Assert.Equal(53, record.DestinationPort);
        Assert.Equal("UDP", record.Protocol);
        Assert.Null(record.ProcessName);
        Assert.Null(record.IsVpn);
        Assert.Null(record.IsProxy);
    }

    [Fact]
    public void ParseFrame_DecodesNullLoopbackIpv4Header()
    {
        var ipPacket = BuildIpv4UdpPacket();
        var frame = new byte[ipPacket.Length + 4];
        frame[0] = 2; // AF_INET in host byte order.
        ipPacket.CopyTo(frame, 4);

        var record = new PacketHandler().ParseFrame(frame, (LinkLayers)0);

        Assert.NotNull(record);
        Assert.Equal("10.0.0.1", record.Source);
        Assert.Equal("10.0.0.2", record.Destination);
        Assert.Equal("UDP", record.Protocol);
    }

    [Fact]
    public void ParseFrame_SurfacesArpNeighborPresenceWithoutPretendingItIsIpTraffic()
    {
        var frame = NpcapArpDiscovery.BuildRequest(
            PhysicalAddress.Parse("021122334455"),
            IPAddress.Parse("192.168.1.10"),
            IPAddress.Parse("192.168.1.42"));

        var record = new PacketHandler().ParseFrame(frame, LinkLayers.Ethernet);

        Assert.NotNull(record);
        Assert.Equal("ARP", record.Protocol);
        Assert.Equal("192.168.1.10", record.Source);
        Assert.Equal("192.168.1.42", record.Destination);
        Assert.Equal("02:11:22:33:44:55", record.MacSource);
        Assert.Equal("FF:FF:FF:FF:FF:FF", record.MacDestination);
        Assert.Contains("Who has 192.168.1.42", record.Info);
        Assert.Null(record.IpVersion);
        Assert.False(record.IsTcp);
        Assert.False(record.IsUdp);
    }

    [Fact]
    public void ParseFrame_SurfacesArpReplyFromSelectedNeighbor()
    {
        var localMac = PhysicalAddress.Parse("021122334455").GetAddressBytes();
        var peerMac = PhysicalAddress.Parse("02AABBCCDDEE").GetAddressBytes();
        var frame = NpcapArpDiscovery.BuildRequest(
            new PhysicalAddress(localMac),
            IPAddress.Parse("192.168.1.10"),
            IPAddress.Parse("192.168.1.42"));
        localMac.CopyTo(frame, 0);
        peerMac.CopyTo(frame, 6);
        frame[20] = 0;
        frame[21] = 2; // ARP reply
        peerMac.CopyTo(frame, 22);
        IPAddress.Parse("192.168.1.42").GetAddressBytes().CopyTo(frame, 28);
        localMac.CopyTo(frame, 32);
        IPAddress.Parse("192.168.1.10").GetAddressBytes().CopyTo(frame, 38);

        var record = new PacketHandler().ParseFrame(frame, LinkLayers.Ethernet);

        Assert.NotNull(record);
        Assert.Equal("ARP", record.Protocol);
        Assert.Equal("192.168.1.42", record.Source);
        Assert.Equal("192.168.1.10", record.Destination);
        Assert.Equal("02:AA:BB:CC:DD:EE", record.MacSource);
        Assert.Equal("02:11:22:33:44:55", record.MacDestination);
        Assert.Equal("192.168.1.42 is at 02:AA:BB:CC:DD:EE", record.Info);
    }

    private static byte[] BuildIpv4UdpPacket()
    {
        var packet = new byte[28];
        packet[0] = 0x45;
        packet[2] = 0;
        packet[3] = 28;
        packet[8] = 64;
        packet[9] = 17;
        packet[12] = 10;
        packet[15] = 1;
        packet[16] = 10;
        packet[19] = 2;
        packet[20] = 0xCF;
        packet[21] = 0x08; // 53000
        packet[22] = 0;
        packet[23] = 53;
        packet[24] = 0;
        packet[25] = 8;
        return packet;
    }
}
