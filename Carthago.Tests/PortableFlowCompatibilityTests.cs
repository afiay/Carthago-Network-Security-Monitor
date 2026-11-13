// SPDX-License-Identifier: MIT
using Carthago.Services;
using Carthago.Services.Flow;
using Xunit;

namespace Carthago.Tests;
public sealed class PortableFlowCompatibilityTests
{
    [Fact]
    public void FormerWindowsAssemblyForwardsFlowTypes()
    {
        var legacy=typeof(PacketHandler).Assembly;
        foreach(var type in new[]{typeof(FlowKey),typeof(HandshakeBuffer),typeof(LatencyTracker)})
        {
            Assert.Contains(type,legacy.GetForwardedTypes());
            Assert.Same(type,Type.GetType(type.FullName+", "+legacy.GetName().Name,throwOnError:true));
        }
    }
}
