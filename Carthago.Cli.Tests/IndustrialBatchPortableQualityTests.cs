// SPDX-License-Identifier: MIT
using System.Text;
using Carthago.Models;
using Carthago.Services.ProtocolIntelligence;
using Carthago.Tests;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class IndustrialBatchPortableQualityTests
{
    public static System.Collections.Generic.IEnumerable<object[]> Frames=>IndustrialBatchWireFixtures.PositiveFrames();
    [Theory]
    [MemberData(nameof(Frames))]
    public void PortableRawCaptureAndTruncation(IndustrialBatchOperation operation,int port,bool tcp,bool same,string hex)
    {
        var bytes=IndustrialBatchWireFixtures.Decode(hex);
        var r=Assert.IsType<TrafficRecord>(IndustrialBatchWireFixtures.Capture(bytes,port,tcp,same));
        Assert.Equal(operation,r.IndustrialOperation);
        Assert.Equal(IndustrialBatchInspector.Label(operation),r.ApplicationProtocol);
        foreach(string variant in new[]{"truncated","trailing","ip-incomplete","ip-fragment","wrong-port","wrong-transport"})
        {
            var bad=IndustrialBatchWireFixtures.Capture(bytes,port,tcp,same,variant);
            if(bad!=null)Assert.NotEqual(operation,bad.IndustrialOperation);
        }
    }
    [Fact]
    public void IndependentDnpCrcKnownVector()
    {
        var bytes=Encoding.ASCII.GetBytes("123456789");
        Assert.Equal((ushort)0xEA82,IndustrialBatchWireFixtures.IndependentDnpCrc(bytes));
        Assert.Equal((ushort)0xEA82,Dnp3UnsolicitedBinaryEventInspector.Crc(bytes));
    }
}
