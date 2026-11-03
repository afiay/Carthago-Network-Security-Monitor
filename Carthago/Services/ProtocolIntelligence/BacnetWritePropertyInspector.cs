// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Bounded BACnet/IP unicast BVLC + NPDU + unsegmented ConfirmedRequest
    /// WriteProperty (service 15) shape. No BACnet object IDs, property IDs,
    /// values, addresses or raw bytes are retained. This is NOT an authenticated
    /// command, successful property write or server response.
    /// </summary>
    public static class BacnetWritePropertyInspector
    {
        private const int MaxDatagramBytes = 1476;

        public static bool TryInspect(ReadOnlySpan<byte> datagram,
            bool verifiedCompletePlaintextUdpDatagram,
            out BacnetWritePropertyObservation observation)
        {
            observation = default;
            if (!verifiedCompletePlaintextUdpDatagram
                || datagram.Length is < 21 or > MaxDatagramBytes
                || datagram[0] != 0x81 || datagram[1] != 0x0a
                || BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(2, 2)) != datagram.Length
                || datagram[4] != 0x01)
                return false;

            // NPDU: local unicast, no routed source/destination, no network
            // layer message; confirmed requests require an expected reply.
            byte control = datagram[5];
            if ((control & 0xF8) != 0 || (control & 0x04) == 0)
                return false;

            // APDU: unsegmented ConfirmedRequest, invoke ID, service choice 15.
            // Segmented APDUs require reassembly which this fast path lacks.
            // Segmentation, more-follows and reserved bit zero are excluded;
            // segmented-response-accepted is valid for an unsegmented request.
            if ((datagram[6] & 0xFD) != 0
                || (datagram[7] & 0x0F) > 5 || (datagram[7] >> 4) > 7
                || datagram[9] != 0x0F)
                return false;

            int position = 10;
            if (datagram[position++] != 0x0c || datagram.Length - position < 4)
                return false;
            position += 4; // Object Identifier context tag [0], not retained.

            if (position >= datagram.Length)
                return false;
            byte propertyTag = datagram[position++];
            int propertyLength = propertyTag & 0x07;
            if ((propertyTag & 0xF8) != 0x18 || propertyLength is < 1 or > 4
                || propertyLength > datagram.Length - position)
                return false;
            position += propertyLength; // Property Identifier context [1].

            // First iteration accepts one scalar application-encoded value in
            // context [3], with an optional standard priority [4]. Structured
            // or array values are deliberately unsupported and fail closed.
            if (position >= datagram.Length || datagram[position++] != 0x3e
                || position >= datagram.Length)
                return false;
            byte valueTag = datagram[position++];
            int valueLength = valueTag & 0x07;
            int applicationTag = valueTag >> 4;
            // Conservative subset: unsigned, signed, REAL and enumerated.
            // NULL, Boolean, double, character/bit strings, extended tags and
            // arbitrary constructed values cannot be validated by this parser.
            if ((valueTag & 0x08) != 0
                || (applicationTag is not (2 or 3 or 4 or 9))
                || (applicationTag == 4 && valueLength != 4)
                || valueLength is < 1 or > 4
                || valueLength > datagram.Length - position)
                return false;
            position += valueLength;
            if (position >= datagram.Length || datagram[position++] != 0x3f)
                return false;

            if (position < datagram.Length)
            {
                if (datagram[position++] != 0x49 || position >= datagram.Length
                    || datagram[position] is < 1 or > 16)
                    return false;
                position++;
            }
            if (position != datagram.Length)
                return false;

            observation = new BacnetWritePropertyObservation(
                datagram[8], datagram.Length, HasObjectAndPropertyTarget: true);
            return true;
        }
    }

    /// <summary>Untrusted wire request shape, not an authenticated write outcome.</summary>
    public readonly record struct BacnetWritePropertyObservation(
        byte InvokeId, int BytesConsumed, bool HasObjectAndPropertyTarget);
}
