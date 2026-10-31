// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Isolated RFC 8489 STUN Binding envelope inspector. Caller attests one
    /// complete UDP payload; no ICE/TURN session, NAT mapping, credential,
    /// integrity, fingerprint, or authorization verification is performed.
    /// Transaction IDs, addresses, usernames and attribute values are not retained.
    /// </summary>
    public static class StunBindingMessageInspector
    {
        public static bool TryInspect(ReadOnlySpan<byte> datagram,
            bool verifiedCompleteUdpPayload, out StunBindingObservation observation)
        {
            observation = default;
            if (!verifiedCompleteUdpPayload || datagram.Length is < 20 or > 2048
                || (datagram[0] & 0xc0) != 0
                || BinaryPrimitives.ReadUInt32BigEndian(datagram.Slice(4, 4)) != 0x2112a442)
                return false;

            ushort messageType = BinaryPrimitives.ReadUInt16BigEndian(datagram);
            int method = (messageType & 0x000f)
                | ((messageType & 0x00e0) >> 1)
                | ((messageType & 0x3e00) >> 2);
            if (method != 1) // Binding only, not arbitrary TURN/ICE methods.
                return false;

            int declaredLength = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(2, 2));
            if ((declaredLength & 3) != 0 || declaredLength != datagram.Length - 20)
                return false; // Strict one-message UDP profile; no trailing bytes.

            byte messageClass = (byte)(((messageType >> 4) & 1)
                | (((messageType >> 8) & 1) << 1));
            int count = 0;
            bool hasIntegrityAttribute = false;
            bool hasFingerprintAttribute = false;
            for (int offset = 20; offset < datagram.Length;)
            {
                if (datagram.Length - offset < 4 || ++count > 64)
                    return false;
                ushort type = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(offset, 2));
                int valueLength = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(offset + 2, 2));
                int paddedLength = (valueLength + 3) & ~3;
                if (paddedLength > datagram.Length - offset - 4)
                    return false;

                if (type == 0x0008 || type == 0x001c)
                {
                    if (hasIntegrityAttribute || valueLength != (type == 0x0008 ? 20 : 32))
                        return false;
                    hasIntegrityAttribute = true; // Presence only; HMAC NOT verified.
                }
                if (type == 0x8028)
                {
                    if (hasFingerprintAttribute || valueLength != 4
                        || offset + 4 + paddedLength != datagram.Length)
                        return false;
                    hasFingerprintAttribute = true; // CRC NOT verified.
                }
                offset += 4 + paddedLength;
            }

            observation = new StunBindingObservation(messageClass, count,
                hasIntegrityAttribute, hasFingerprintAttribute, datagram.Length);
            return true;
        }
    }

    public readonly record struct StunBindingObservation(
        byte MessageClass, int AttributeCount, bool HasIntegrityAttribute,
        bool HasFingerprintAttribute, int DatagramLength);
}
