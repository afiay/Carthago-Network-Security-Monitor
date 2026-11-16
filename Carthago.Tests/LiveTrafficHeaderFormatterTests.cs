// SPDX-License-Identifier: MIT
using Carthago.Models;
using Carthago.Views;
using Xunit;

namespace Carthago.Tests;

public sealed class LiveTrafficHeaderFormatterTests
{
    [Fact]
    public void TcpSynAckHasReadableAndHexadecimalFlags()
    {
        var record = new TrafficRecord { Protocol = "TCP", IsTcp = true, TcpFlags = 0x12, Flags = "SYN, ACK" };
        Assert.Equal("SYN, ACK", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.TcpText));
        Assert.Equal("0x012 (18)", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.TcpRaw));
        Assert.Equal("N/A", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.IcmpType));
        Assert.Equal("N/A", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.IcmpCode));
    }

    [Fact]
    public void TcpNumericFlagsProvideTextFallbackWithoutChangingRawRecord()
    {
        var record = new TrafficRecord { Protocol = "TCP", TcpFlags = 0x118 };
        Assert.Equal("NS, ACK, PSH", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.TcpText));
        Assert.Equal("0x118 (280)", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.TcpRaw));
        Assert.Null(record.Flags);
    }

    [Fact]
    public void TcpZeroFlagsAreObservedZeroNotMissing()
    {
        var record = new TrafficRecord { Protocol = "TCP", TcpFlags = 0 };
        Assert.Equal("NONE", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.TcpText));
        Assert.Equal("0x000 (0)", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.TcpRaw));
    }

    [Fact]
    public void TcpMissingHeaderIsUnavailableNotNotApplicable()
    {
        var record = new TrafficRecord { Protocol = "TCP", IsTcp = true };
        Assert.Equal("—", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.TcpText));
        Assert.Equal("—", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.TcpRaw));
    }

    [Fact]
    public void TextualFlagsDoNotInventRawNumericEvidence()
    {
        var record = new TrafficRecord { Protocol = "TCP", Flags = "SYN" };
        Assert.Equal("SYN", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.TcpText));
        Assert.Equal("—", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.TcpRaw));
    }

    [Theory]
    [InlineData("ICMP", 0x0800, "8", "0")]
    [InlineData("ICMPv6", 0x8000, "128", "0")]
    [InlineData("ICMP", 0x0303, "3", "3")]
    [InlineData("icmpv6", 0x8100, "129", "0")]
    public void IcmpCombinedWireValueIsSplitIntoTypeAndCode(string protocol, int wire, string type, string code)
    {
        var record = new TrafficRecord { Protocol = protocol, IcmpTypeCode = checked((ushort)wire) };
        Assert.Equal(type, LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.IcmpType));
        Assert.Equal(code, LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.IcmpCode));
        Assert.Equal("N/A", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.TcpText));
        Assert.Equal("N/A", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.TcpRaw));
    }

    [Fact]
    public void IcmpMissingHeaderIsUnavailable()
    {
        var record = new TrafficRecord { Protocol = "ICMP" };
        Assert.Equal("—", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.IcmpType));
        Assert.Equal("—", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.IcmpCode));
    }

    [Theory]
    [InlineData("UDP")]
    [InlineData("ARP")]
    public void OtherProtocolsAreNotApplicable(string protocol)
    {
        var record = new TrafficRecord { Protocol = protocol };
        Assert.Equal("N/A", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.IcmpType));
        Assert.Equal("N/A", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.IcmpCode));
        Assert.Equal("N/A", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.TcpText));
        Assert.Equal("N/A", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.TcpRaw));
    }

    [Fact]
    public void MissingProtocolCannotBeMisreportedAsNotApplicable()
    {
        var record = new TrafficRecord();
        Assert.Equal("—", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.IcmpType));
        Assert.Equal("—", LiveTrafficHeaderFormatter.Format(record, LiveTrafficHeaderFormatter.TcpRaw));
        Assert.Equal("—", LiveTrafficHeaderFormatter.Format(null, LiveTrafficHeaderFormatter.TcpText));
    }
}
