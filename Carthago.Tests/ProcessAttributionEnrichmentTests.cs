using System;
using System.Net;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class ProcessAttributionEnrichmentTests
{
    [Fact]
    public void Udp_Distinct_Owners_Are_Ambiguous_In_Either_Order()
    {
        var first = new WindowsProcessResolver.UdpOwnerSelection();
        first.Observe(100);
        first.Observe(200);
        first.Observe(100);
        Assert.Equal(0, first.Pid);
        var second = new WindowsProcessResolver.UdpOwnerSelection();
        second.Observe(200);
        second.Observe(100);
        Assert.Equal(0, second.Pid);
    }

    [Fact]
    public void Udp_Multiple_Bindings_For_Same_Owner_Are_Not_Ambiguous()
    {
        var owners = new WindowsProcessResolver.UdpOwnerSelection();
        owners.Observe(100);
        owners.Observe(100);
        Assert.Equal(100, owners.Pid);
    }

    [Fact]
    public void Udp_Unknown_Owner_Does_Not_Confirm_A_Different_Owner()
    {
        var owners = new WindowsProcessResolver.UdpOwnerSelection();
        owners.Observe(0);
        owners.Observe(100);
        Assert.Equal(0, owners.Pid);
    }

    [Fact]
    public void Process_Cache_Requires_Matching_Creation_Time()
    {
        var start = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        Assert.True(WindowsProcessResolver.MatchesProcessIdentity(start, start));
        Assert.False(WindowsProcessResolver.MatchesProcessIdentity(start, start.AddSeconds(1)));
        Assert.False(WindowsProcessResolver.MatchesProcessIdentity(start, null));
        Assert.False(WindowsProcessResolver.MatchesProcessIdentity(null, start));
        Assert.False(WindowsProcessResolver.MatchesProcessIdentity(null, null));
    }

    [Fact]
    public void Mapped_Ipv4_And_Invalid_Address_Are_Handled_Conservatively()
    {
        Assert.True(WindowsProcessResolver.AddressMatchesForTests("::ffff:192.168.1.10", IPAddress.Parse("192.168.1.10")));
        Assert.True(WindowsProcessResolver.AddressMatchesForTests("::ffff:192.168.1.10", IPAddress.Any));
        Assert.False(WindowsProcessResolver.AddressMatchesForTests("invalid", IPAddress.Any));
        Assert.False(WindowsProcessResolver.AddressMatchesForTests("192.168.1.10", IPAddress.IPv6Any));
    }
}
