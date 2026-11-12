using System.Collections.Generic;
using System.Net;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class EndpointIpEnrichmentTests
{
    [Theory]
    [InlineData("192.168.1.1", "Private")]
    [InlineData("10.0.0.1", "Private")]
    [InlineData("172.31.0.1", "Private")]
    [InlineData("172.32.0.1", "Public")]
    [InlineData("100.64.0.1", "SharedCGNAT")]
    [InlineData("100.128.0.1", "Public")]
    [InlineData("127.0.0.1", "Loopback")]
    [InlineData("::ffff:127.0.0.1", "Loopback")]
    [InlineData("::ffff:192.168.1.1", "Private")]
    [InlineData("169.254.1.1", "LinkLocal")]
    [InlineData("224.0.0.1", "Multicast")]
    [InlineData("255.255.255.255", "Reserved")]
    [InlineData("192.0.2.1", "Documentation")]
    [InlineData("198.18.0.1", "Benchmark")]
    [InlineData("::", "UnspecifiedOrReserved")]
    [InlineData("::1", "Loopback")]
    [InlineData("fc00::1", "Private")]
    [InlineData("fe80::1", "LinkLocal")]
    [InlineData("ff02::1", "Multicast")]
    [InlineData("2001:db8::1", "Documentation")]
    [InlineData("3fff::1", "Documentation")]
    [InlineData("2001:4860:4860::8888", "Public")]
    [InlineData("8.8.8.8", "Public")]
    [InlineData("not-an-ip", "Unknown")]
    public void Scope_Is_Conservative(string ip, string scope)
        => Assert.Equal(scope, EndpointIpEnrichment.Classify(ip));

    [Fact]
    public void Private_Address_Is_Not_Automatically_Local()
    {
        var record = new TrafficRecord { Source = "192.168.1.10", Destination = "192.168.1.20" };
        EndpointIpEnrichment.Apply(record, new HashSet<IPAddress> { IPAddress.Parse("192.168.1.10") });
        Assert.Equal("Private", record.SrcIpScope);
        Assert.Equal("Private", record.DstIpScope);
        Assert.True(record.SrcIsLocalHost);
        Assert.False(record.DstIsLocalHost);
    }

    [Fact]
    public void Public_Local_Address_And_Unknown_Inventory_Are_Distinct()
    {
        var record = new TrafficRecord { Source = "8.8.8.8", Destination = "1.1.1.1" };
        EndpointIpEnrichment.Apply(record, new HashSet<IPAddress> { IPAddress.Parse("8.8.8.8") });
        Assert.True(record.SrcIsLocalHost);
        Assert.Equal("Public", record.SrcIpScope);
        EndpointIpEnrichment.Apply(record, null);
        Assert.Null(record.SrcIsLocalHost);
        Assert.Null(record.DstIsLocalHost);
    }
}
