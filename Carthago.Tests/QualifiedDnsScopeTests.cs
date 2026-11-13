// SPDX-License-Identifier: MIT
using System;
using Carthago.Services.Baseline;
using Xunit;

namespace Carthago.Tests;

public sealed class QualifiedDnsScopeTests
{
    [Fact]
    public void Scope_Is_Exact_And_Unambiguous()
    {
        var scope = QualifiedDnsScope.Create("192.0.2.1", "sensor-a", "nic-a", "network-a");
        Assert.Equal(scope, QualifiedDnsScope.Create("::ffff:192.0.2.1", "sensor-a", "nic-a", "network-a"));
        Assert.NotEqual(scope, QualifiedDnsScope.Create("192.0.2.2", "sensor-a", "nic-a", "network-a"));
        Assert.NotEqual(scope, QualifiedDnsScope.Create("192.0.2.1", "sensor-b", "nic-a", "network-a"));
        Assert.NotEqual(scope, QualifiedDnsScope.Create("192.0.2.1", "sensor-a", "nic-b", "network-a"));
        Assert.NotEqual(scope, QualifiedDnsScope.Create("192.0.2.1", "sensor-a", "nic-a", "network-b"));
        Assert.NotEqual(QualifiedDnsScope.Create("192.0.2.1", "a,b", "c", "d"),
            QualifiedDnsScope.Create("192.0.2.1", "a", "b,c", "d"));
        Assert.NotEqual("dns.domain", QualifiedDnsScope.ObservationKind);
    }

    [Fact]
    public void Malformed_Unicode_Cannot_Alias_A_Valid_Identity()
    {
        var high = new string((char)0xD800, 1);
        var low = new string((char)0xDC00, 1);
        Assert.Throws<ArgumentException>(() => QualifiedDnsScope.Create("192.0.2.1", high, "nic", "network"));
        Assert.Throws<ArgumentException>(() => QualifiedDnsScope.Create("192.0.2.1", "sensor", low, "network"));
        Assert.Throws<ArgumentException>(() => QualifiedDnsScope.Create("192.0.2.1", "sensor", "nic", high + "x"));
        var valid = QualifiedDnsScope.Create("192.0.2.1", "\uFFFD", "nic", "network");
        Assert.NotEqual(valid, QualifiedDnsScope.Create("192.0.2.1", char.ConvertFromUtf32(0x1F600), "nic", "network"));
    }

    [Theory]
    [InlineData("0.0.0.0", "sensor", "nic", "network")]
    [InlineData("::ffff:0.0.0.0", "sensor", "nic", "network")]
    [InlineData("::", "sensor", "nic", "network")]
    [InlineData("invalid", "sensor", "nic", "network")]
    [InlineData("192.0.2.1", "", "nic", "network")]
    [InlineData("192.0.2.1", "sensor", " ", "network")]
    [InlineData("192.0.2.1", "sensor", "nic", " network")]
    public void Missing_Or_Ambiguous_Identity_Is_Rejected(string source, string sensor,
        string nic, string network)
    {
        Assert.Throws<ArgumentException>(() => QualifiedDnsScope.Create(source, sensor, nic, network));
    }
}
