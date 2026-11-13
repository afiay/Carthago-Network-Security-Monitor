// SPDX-License-Identifier: MIT
using Carthago.Services;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableProtocolCoreTests
{
    [Fact]
    public void ParsersHaveSinglePortableAssemblyOwner()
    {
        var core = typeof(DnsWireNameCodec).Assembly;
        Assert.Equal("Carthago.Core", core.GetName().Name);
        Assert.Same(core, typeof(DnsWireName).Assembly);
        Assert.Same(core, typeof(DnsAddressObservationInspector).Assembly);
        Assert.Same(core, typeof(BacnetEventDisableInspector).Assembly);
        Assert.DoesNotContain(core.GetReferencedAssemblies(), a =>
            a.Name is "Carthago" or "PresentationFramework" or "PresentationCore" or "WindowsBase");
    }

    [Fact]
    public void BinaryDnsLabelsRemainLosslessAndCannotBecomeAsciiNames()
    {
        byte[] wire = { 3, 0x41, 0, 0xff, 0 };
        Assert.True(DnsWireNameCodec.TryReadQuestion(wire, 0, out var name, out int end, out _));
        Assert.Equal(wire.Length, end);
        Assert.Equal("A", System.Text.Encoding.ASCII.GetString(name!.GetLabelBytes(0)[..1]));
        Assert.Equal(new byte[] { 0x41, 0, 0xff }, name.GetLabelBytes(0));
        Assert.False(DnsWireNameCodec.TryGetSafeAsciiQName(name, out _));
        Assert.True(DnsWireNameCodec.TryFromBase64Labels(DnsWireNameCodec.ToBase64Labels(name),
            out var roundTrip, out _));
        Assert.Equal(DnsWireNameCodec.CanonicalIdentityKey(name),
            DnsWireNameCodec.CanonicalIdentityKey(roundTrip!));
    }

    [Fact]
    public void ForwardCompressionPointerIsRejected()
    {
        Assert.False(DnsWireNameCodec.TryReadQuestion(new byte[] { 0xc0, 2, 0 }, 0,
            out _, out _, out var error));
        Assert.Equal(DnsWireNameError.InvalidCompressionPointer, error);
    }

    private static byte[] DnsResponse() => new byte[]
    {
        0x12,0x34,0x81,0x80,0,1,0,1,0,0,0,0,
        7,101,120,97,109,112,108,101,3,99,111,109,0,0,1,0,1,
        0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,192,0,2,1
    };

    [Fact]
    public void DnsAddressResponseRetainsQuestionAndBoundedAnswer()
    {
        Assert.True(DnsAddressObservationInspector.TryInspect(DnsResponse(), out var observation));
        Assert.NotNull(observation);
        Assert.True(observation!.IsResponse);
        Assert.Equal((ushort)0x1234, observation.TransactionId);
        Assert.Equal("example.com", observation.Name);
        var answer = Assert.Single(observation.Answers);
        Assert.Equal("192.0.2.1", answer.Address);
        Assert.Equal(60u, answer.Ttl);
    }

    [Fact]
    public void AllTruncatedDnsResponsesFailClosed()
    {
        var wire = DnsResponse();
        for (int length = 0; length < wire.Length; length++)
        {
            Assert.False(DnsAddressObservationInspector.TryInspect(wire.AsSpan(0, length), out var observation));
            Assert.Null(observation);
        }
        Assert.False(DnsAddressObservationInspector.TryInspect(wire.Concat(new byte[] { 0 }).ToArray(), out _));
    }

    private static byte[] BacnetRequest() => new byte[]
    {
        0x81,0x0a,0,22,1,4,0,5,7,15,0x0c,0,0,0,1,0x19,35,0x3e,0x82,5,0,0x3f
    };

    [Fact]
    public void BacnetExactDisableRequestMatchesButPartialEnableDoesNot()
    {
        var wire = BacnetRequest();
        Assert.True(BacnetEventDisableInspector.TryInspect(wire));
        wire[20] = 0x80;
        Assert.False(BacnetEventDisableInspector.TryInspect(wire));
    }

    [Fact]
    public void BacnetTruncationsAndTrailingDataFailClosed()
    {
        var wire = BacnetRequest();
        for (int length = 0; length < wire.Length; length++)
            Assert.False(BacnetEventDisableInspector.TryInspect(wire.AsSpan(0, length)));
        Assert.False(BacnetEventDisableInspector.TryInspect(wire.Concat(new byte[] { 0 }).ToArray()));
    }
}
