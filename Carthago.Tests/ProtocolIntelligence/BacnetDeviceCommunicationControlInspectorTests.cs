// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Synthetic BACnet/IP APDU only.
using System;
using System.Collections.Generic;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence;

public sealed class BacnetDeviceCommunicationControlInspectorTests
{
    internal static byte[] Request(byte disableState = 2, bool duration = true,
        bool twoByteDuration = false,
        byte service = 0x11, byte apduFlags = 0x00,
        byte npduControl = 0x04, byte function = 0x0a,
        byte[]? trailing = null)
    {
        var body = new List<byte> { 0x01, npduControl, apduFlags, 0x05, 0x39, service };
        if (duration)
            body.AddRange(twoByteDuration
                ? new byte[] { 0x0a, 0x00, 0x05 }
                : new byte[] { 0x09, 0x05 }); // context [0] five minutes
        body.AddRange(new byte[] { 0x19, disableState }); // context [1] ENUMERATED
        if (trailing != null)
            body.AddRange(trailing);
        var packet = new byte[4 + body.Count];
        packet[0] = 0x81;
        packet[1] = function;
        packet[2] = (byte)(packet.Length >> 8);
        packet[3] = (byte)packet.Length;
        body.CopyTo(packet, 4);
        return packet;
    }

    [Theory]
    [InlineData((byte)1)]
    [InlineData((byte)2)]
    public void UnsegmentedDisableRequestsHaveBoundedNonSensitiveShape(byte disableState)
    {
        var packet = Request(disableState);
        Assert.True(BacnetDeviceCommunicationControlInspector.TryInspect(packet, true, out var observed));
        Assert.Equal(disableState, observed.DisableState);
        Assert.Equal(packet.Length, observed.BytesConsumed);
        Assert.Equal((byte)0x39, observed.InvokeId);
        Assert.True(observed.HasTimeDuration);
        Assert.DoesNotContain("password", observed.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void IndefiniteDisableWithNoTimeDurationIsAnObservedRequest()
    {
        Assert.True(BacnetDeviceCommunicationControlInspector.TryInspect(
            Request(duration: false), true, out var observed));
        Assert.False(observed.HasTimeDuration);
        Assert.True(BacnetDeviceCommunicationControlInspector.TryInspect(
            Request(twoByteDuration: true), true, out var twoOctet));
        Assert.True(twoOctet.HasTimeDuration);
    }

    [Theory]
    [InlineData(0x00)] // ENABLE, not an interruption attempt
    [InlineData(0x03)] // unknown enable/disable enumeration
    public void EnableOrUnknownStateCannotQualify(byte disableState)
        => Assert.False(BacnetDeviceCommunicationControlInspector.TryInspect(
            Request(disableState), true, out _));

    [Fact]
    public void NonDccOrAmbiguousNetworkFramesFailClosed()
    {
        Assert.False(BacnetDeviceCommunicationControlInspector.TryInspect(Request(service: 0x0f), true, out _));
        Assert.False(BacnetDeviceCommunicationControlInspector.TryInspect(Request(apduFlags: 0x08), true, out _));
        Assert.False(BacnetDeviceCommunicationControlInspector.TryInspect(Request(apduFlags: 0x01), true, out _));
        Assert.False(BacnetDeviceCommunicationControlInspector.TryInspect(Request(apduFlags: 0x20), true, out _)); // SimpleACK PDU
        Assert.False(BacnetDeviceCommunicationControlInspector.TryInspect(Request(apduFlags: 0x50), true, out _)); // Error PDU
        Assert.False(BacnetDeviceCommunicationControlInspector.TryInspect(Request(apduFlags: 0x60), true, out _)); // Reject PDU
        Assert.False(BacnetDeviceCommunicationControlInspector.TryInspect(Request(apduFlags: 0x70), true, out _)); // Abort PDU
        Assert.False(BacnetDeviceCommunicationControlInspector.TryInspect(Request(npduControl: 0x84), true, out _));
        Assert.False(BacnetDeviceCommunicationControlInspector.TryInspect(Request(function: 0x0b), true, out _));
        Assert.False(BacnetDeviceCommunicationControlInspector.TryInspect(Request(), false, out _));
    }

    [Fact]
    public void TruncationMalformedContextDurationAndPasswordVariantFailClosed()
    {
        var packet = Request();
        Assert.False(BacnetDeviceCommunicationControlInspector.TryInspect(
            packet.AsSpan(0, packet.Length - 1), true, out _));
        packet[3]--;
        Assert.False(BacnetDeviceCommunicationControlInspector.TryInspect(packet, true, out _));

        packet = Request();
        packet[10] = 0x0b; // [0] wrong context-encoded length
        Assert.False(BacnetDeviceCommunicationControlInspector.TryInspect(packet, true, out _));
        packet = Request();
        packet[12] = 0x18; // [1] zero-byte value
        Assert.False(BacnetDeviceCommunicationControlInspector.TryInspect(packet, true, out _));
        packet = Request(trailing: new byte[] { 0x29, 0x41 }); // [2] password intentionally unsupported
        Assert.False(BacnetDeviceCommunicationControlInspector.TryInspect(packet, true, out _));
        packet = Request();
        packet[7] = 0xff; // unsupported max-segments / max-APDU encoding
        Assert.False(BacnetDeviceCommunicationControlInspector.TryInspect(packet, true, out _));
    }
}
