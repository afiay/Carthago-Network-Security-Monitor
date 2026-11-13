// SPDX-License-Identifier: MIT
using Carthago.Services;
using Carthago.Services.Fingerprints;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests;

public sealed class PortableFingerprintCompatibilityTests
{
    [Fact]
    public void WindowsAssemblyForwardsAllRelocatedPublicTypes()
    {
        var legacy=typeof(PacketHandler).Assembly;
        var types=new[]{typeof(HttpJa4H),typeof(TlsJa4),typeof(TcpJa4T),typeof(SshJa4SSH),typeof(Hassh),
            typeof(Resp2CommandInspector),typeof(Resp2CommandKind),typeof(Resp2CommandObservation),
            typeof(Resp2SimpleReplyInspector),typeof(Resp2SimpleReplyKind)};
        foreach(var type in types)
        {
            Assert.Contains(type,legacy.GetForwardedTypes());
            Assert.Same(type,Type.GetType(type.FullName+", "+legacy.GetName().Name,throwOnError:true));
        }
    }
}
