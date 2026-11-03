// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Bounded BACnet/IP unicast, unsegmented ConfirmedRequest service 17
    /// DeviceCommunicationControl disable-attempt shape. No authentication,
    /// device acknowledgement, or actually disabled traffic is established.
    /// This narrow subset excludes password-bearing and routed requests.
    /// </summary>
    public static class BacnetDeviceCommunicationControlInspector
    {
        private const int MaxDatagramBytes = 1476;

        public static bool TryInspect(ReadOnlySpan<byte> datagram,
            bool verifiedCompletePlaintextUdpDatagram,
            out BacnetDeviceCommunicationControlObservation observation)
        {
            observation = default;
            if (!verifiedCompletePlaintextUdpDatagram
                || datagram.Length is < 12 or > MaxDatagramBytes
                || datagram[0] != 0x81 || datagram[1] != 0x0a
                || BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(2, 2)) != datagram.Length
                || datagram[4] != 0x01)
                return false;

            // Local unicast NPDU, expecting reply, no routing addresses or
            // unsupported network-layer extensions.
            byte control = datagram[5];
            if ((control & 0xF8) != 0 || (control & 0x04) == 0)
                return false;

            // Only an unsegmented ConfirmedRequest PDU. The APDU reserved bit
            // and more-follows/segmented bits must be clear. Service choice 17.
            if ((datagram[6] & 0xFD) != 0
                || (datagram[7] & 0x0F) > 5 || (datagram[7] >> 4) > 7
                || datagram[9] != 0x11)
                return false;

            int cursor = 10;
            bool hasDuration = false;
            if (cursor < datagram.Length && (datagram[cursor] == 0x09 || datagram[cursor] == 0x0a))
            {
                int durationLength = datagram[cursor++] & 0x07;
                if (durationLength > datagram.Length - cursor)
                    return false;
                cursor += durationLength; // [0] Unsigned16, not retained.
                hasDuration = true;
            }

            // [1] ENUMERATED: ENABLE(0) is not a disable attempt; 1 is
            // legacy disable and 2 is disable-initiation. Both are attempts,
            // not evidence that a device accepted the command.
            if (datagram.Length - cursor != 2 || datagram[cursor++] != 0x19)
                return false;
            byte state = datagram[cursor];
            if (state is not (1 or 2))
                return false;

            observation = new BacnetDeviceCommunicationControlObservation(
                datagram[8], datagram.Length, state, hasDuration);
            return true;
        }
    }

    /// <summary>Privacy-minimal wire request shape, never a controller outcome.</summary>
    public readonly record struct BacnetDeviceCommunicationControlObservation(
        byte InvokeId, int BytesConsumed, byte DisableState, bool HasTimeDuration);
}
