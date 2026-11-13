// SPDX-License-Identifier: MIT
using Carthago.Services;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests;
public sealed class PortableExchangeCompatibilityTests
{
    [Fact]
    public void FormerWindowsAssemblyForwardsAllRelocatedPublicTypes()
    {
        var legacy=typeof(PacketHandler).Assembly;
        foreach(var type in new[]{typeof(Iec104ApduInspector),typeof(Iec104FrameKind),typeof(Iec104ApduObservation),typeof(OpcUaConnectionInspector),typeof(OpcUaConnectionKind),typeof(OpcUaConnectionObservation),typeof(LdapMessageInspector),typeof(LdapMessageObservation),typeof(LdapSimpleBindObservation),typeof(TftpRequestInspector),typeof(TftpRequestKind),typeof(TftpTransferMode),typeof(TftpRequestObservation)})
        {
            Assert.Contains(type,legacy.GetForwardedTypes());
            Assert.Same(type,Type.GetType(type.FullName+", "+legacy.GetName().Name,throwOnError:true));
        }
    }
}
