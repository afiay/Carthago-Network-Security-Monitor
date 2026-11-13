// SPDX-License-Identifier: MIT
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class TrafficRecordAssemblyCompatibilityTests
{
    [Fact]
    public void WindowsAssemblyForwardsLegacyTrafficRecordType()
    {
        var legacy = typeof(Carthago.Services.PacketHandler).Assembly;
        Assert.Equal("Carthago.Core", typeof(TrafficRecord).Assembly.GetName().Name);
        Assert.Contains(typeof(TrafficRecord), legacy.GetForwardedTypes());
        Assert.Same(typeof(TrafficRecord), System.Type.GetType(
            "Carthago.Models.TrafficRecord, " + legacy.GetName().Name, throwOnError: true));
    }
}
