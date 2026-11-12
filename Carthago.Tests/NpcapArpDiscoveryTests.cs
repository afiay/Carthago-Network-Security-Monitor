using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public class NpcapArpDiscoveryTests
{
    private static readonly PhysicalAddress LocalMac = PhysicalAddress.Parse("0C-DD-24-0B-CE-26");
    private static readonly PhysicalAddress PhoneMac = PhysicalAddress.Parse("02-11-22-33-44-55");
    private static readonly IPAddress LocalIp = IPAddress.Parse("192.168.1.153");
    private static readonly IPAddress PhoneIp = IPAddress.Parse("192.168.1.42");

    [Fact]
    public void RequestIsAnEthernetBroadcastBoundToTheSelectedAdapter()
    {
        var frame = NpcapArpDiscovery.BuildRequest(LocalMac, LocalIp, PhoneIp);

        Assert.Equal(42, frame.Length);
        Assert.Equal("FFFFFFFFFFFF", Convert.ToHexString(frame.AsSpan(0, 6)));
        Assert.Equal("0CDD240BCE26", Convert.ToHexString(frame.AsSpan(6, 6)));
        Assert.Equal("0806", Convert.ToHexString(frame.AsSpan(12, 2)));
        Assert.Equal("0001", Convert.ToHexString(frame.AsSpan(20, 2)));
        Assert.Equal("0CDD240BCE26", Convert.ToHexString(frame.AsSpan(22, 6)));
        Assert.Equal("C0A80199", Convert.ToHexString(frame.AsSpan(28, 4)));
        Assert.Equal("000000000000", Convert.ToHexString(frame.AsSpan(32, 6)));
        Assert.Equal("C0A8012A", Convert.ToHexString(frame.AsSpan(38, 4)));
    }

    [Fact]
    public void ValidReplyReturnsPhoneAddressAndNormalizedUnicastMac()
    {
        var frame = BuildReply(LocalIp);

        var parsed = NpcapArpDiscovery.TryParseReply(frame, LocalIp, out var address, out var mac);

        Assert.True(parsed);
        Assert.Equal(PhoneIp, address);
        Assert.Equal("02:11:22:33:44:55", mac);
    }

    [Fact]
    public void VlanTaggedReplyIsAccepted()
    {
        var untagged = BuildReply(LocalIp);
        var tagged = new byte[untagged.Length + 4];
        untagged.AsSpan(0, 12).CopyTo(tagged);
        new byte[] { 0x81, 0x00, 0x00, 0x07, 0x08, 0x06 }.CopyTo(tagged, 12);
        untagged.AsSpan(14).CopyTo(tagged.AsSpan(18));

        Assert.True(NpcapArpDiscovery.TryParseReply(tagged, LocalIp, out var address, out var mac));
        Assert.Equal(PhoneIp, address);
        Assert.Equal("02:11:22:33:44:55", mac);
    }

    [Fact]
    public void RequestsWrongTargetsAndInvalidSenderMacsAreRejected()
    {
        var request = BuildReply(LocalIp);
        request[21] = 0x01;
        Assert.False(NpcapArpDiscovery.TryParseReply(request, LocalIp, out _, out _));

        var wrongTarget = BuildReply(IPAddress.Parse("192.168.1.99"));
        Assert.False(NpcapArpDiscovery.TryParseReply(wrongTarget, LocalIp, out _, out _));

        var multicastSender = BuildReply(LocalIp);
        multicastSender[22] = 0x01;
        Assert.False(NpcapArpDiscovery.TryParseReply(multicastSender, LocalIp, out _, out _));

        var zeroSender = BuildReply(LocalIp);
        Array.Clear(zeroSender, 22, 6);
        Assert.False(NpcapArpDiscovery.TryParseReply(zeroSender, LocalIp, out _, out _));
    }

    [Fact]
    public void SleepingPhoneFromScopedCacheRemainsSelectableButIsNotCalledADirectReply()
    {
        var gateway = IPAddress.Parse("192.168.1.1");
        var sleepingPhone = IPAddress.Parse("192.168.1.123");
        var merged = NpcapArpDiscovery.MergeNeighborEvidence(
            new[] { gateway, sleepingPhone },
            new Dictionary<string, string>
            {
                [gateway.ToString()] = "02:00:00:00:00:01",
                [sleepingPhone.ToString()] = "22:CF:5A:AD:DD:27",
                ["192.168.2.9"] = "02:00:00:00:00:09"
            },
            new Dictionary<string, string>
            {
                [gateway.ToString()] = "34:5D:9E:D0:51:9B"
            });

        Assert.Equal("34:5D:9E:D0:51:9B", merged[gateway.ToString()]);
        Assert.Equal("22:CF:5A:AD:DD:27", merged[sleepingPhone.ToString()]);
        Assert.DoesNotContain("192.168.2.9", merged.Keys);
    }

    private static byte[] BuildReply(IPAddress targetIp)
    {
        var frame = NpcapArpDiscovery.BuildRequest(LocalMac, LocalIp, PhoneIp);
        LocalMac.GetAddressBytes().CopyTo(frame, 0);
        PhoneMac.GetAddressBytes().CopyTo(frame, 6);
        frame[20] = 0x00;
        frame[21] = 0x02;
        PhoneMac.GetAddressBytes().CopyTo(frame, 22);
        PhoneIp.GetAddressBytes().CopyTo(frame, 28);
        LocalMac.GetAddressBytes().CopyTo(frame, 32);
        targetIp.GetAddressBytes().CopyTo(frame, 38);
        return frame;
    }
}
