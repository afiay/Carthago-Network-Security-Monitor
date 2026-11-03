// SPDX-License-Identifier: MIT
// Synthetic BACnet/IPv4 wire-shape fixtures. Never actual plant traffic.
using System;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence;

public sealed class BacnetWritePropertyInspectorTests
{
    internal static byte[] Request(byte service = 0x0f, byte apduFlags = 0x00,
        byte npduControl = 0x04, byte function = 0x0a)
    {
        // BVLC, NPDU version/control, confirmed request + maxAPDU + invoke ID,
        // service choice, context object[0], property[1], value[3] unsigned=1.
        byte[] body =
        {
            0x01, npduControl, apduFlags, 0x05, 0x2a, service,
            0x0c, 0x00, 0x80, 0x00, 0x01,
            0x19, 0x55, 0x3e, 0x21, 0x01, 0x3f
        };
        byte[] result = new byte[4 + body.Length];
        result[0] = 0x81;
        result[1] = function;
        result[2] = (byte)(result.Length >> 8);
        result[3] = (byte)result.Length;
        body.CopyTo(result, 4);
        return result;
    }

    [Fact]
    public void ConfirmedWritePropertyHasOnlyNonSensitiveShapeAndInvokeId()
    {
        var raw = Request();
        Assert.True(BacnetWritePropertyInspector.TryInspect(raw, true, out var found));
        Assert.Equal((byte)0x2a, found.InvokeId);
        Assert.Equal(raw.Length, found.BytesConsumed);
        Assert.True(found.HasObjectAndPropertyTarget);
        Assert.DoesNotContain("0x55", found.ToString());
    }

    [Theory]
    [InlineData(0x0c)] // ReadProperty
    [InlineData(0x10)] // WritePropertyMultiple
    public void OtherConfirmedServicesAreNotWriteProperty(byte service)
        => Assert.False(BacnetWritePropertyInspector.TryInspect(Request(service), true, out _));

    [Fact]
    public void SegmentsBroadcastNetworkMessagesAndUnattestedBytesFailClosed()
    {
        Assert.False(BacnetWritePropertyInspector.TryInspect(Request(apduFlags: 0x08), true, out _));
        Assert.False(BacnetWritePropertyInspector.TryInspect(Request(apduFlags: 0x01), true, out _));
        Assert.True(BacnetWritePropertyInspector.TryInspect(Request(apduFlags: 0x02), true, out _));
        Assert.False(BacnetWritePropertyInspector.TryInspect(Request(npduControl: 0x84), true, out _));
        Assert.False(BacnetWritePropertyInspector.TryInspect(Request(function: 0x0b), true, out _));
        Assert.False(BacnetWritePropertyInspector.TryInspect(Request(), false, out _));
    }

    [Fact]
    public void TruncatedSpoofedLengthAndMissingValueAreRejected()
    {
        var raw = Request();
        Assert.False(BacnetWritePropertyInspector.TryInspect(raw.AsSpan(0, raw.Length - 1), true, out _));
        raw[3]--;
        Assert.False(BacnetWritePropertyInspector.TryInspect(raw, true, out _));
        raw = Request();
        raw[raw.Length - 3] = 0x3f; // closing tag where value must begin
        Assert.False(BacnetWritePropertyInspector.TryInspect(raw, true, out _));
        raw = Request();
        raw[10] = 0x0b; // wrong context tag for object ID
        Assert.False(BacnetWritePropertyInspector.TryInspect(raw, true, out _));
        raw = Request();
        raw[7] = 0xff; // invalid max-segments / max-APDU encoding
        Assert.False(BacnetWritePropertyInspector.TryInspect(raw, true, out _));
    }

    [Theory]
    [InlineData(0x41)] // REAL encoded with one octet instead of four
    [InlineData(0x01)] // NULL incorrectly claims a data octet
    [InlineData(0x11)] // Boolean is not in the supported scalar subset
    [InlineData(0xF1)] // Extended/reserved application type
    public void UnsupportedOrMalformedScalarApplicationValuesFailClosed(byte valueTag)
    {
        var raw = Request();
        raw[18] = valueTag;
        Assert.False(BacnetWritePropertyInspector.TryInspect(raw, true, out _));
    }
}
