// SPDX-License-Identifier: MIT
using Carthago.Services;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests;
public sealed class PortableIndustrialCompatibilityTests
{
    [Fact]
    public void FormerWindowsAssemblyForwardsAllPublicBacnetTypes()
    {
        var legacy=typeof(PacketHandler).Assembly;
        foreach(var type in new[]{typeof(BacnetBvlcControlInspector),typeof(BvlcControlFunction),typeof(BvlcControlObservation),typeof(BacnetDeviceCommunicationControlInspector),typeof(BacnetDeviceCommunicationControlObservation),typeof(BacnetWritePropertyInspector),typeof(BacnetWritePropertyObservation)})
        {
            Assert.Contains(type,legacy.GetForwardedTypes());
            Assert.Same(type,Type.GetType(type.FullName+", "+legacy.GetName().Name,throwOnError:true));
        }
    }
}
