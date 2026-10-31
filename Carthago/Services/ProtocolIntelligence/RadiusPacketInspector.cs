// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Isolated RFC 2865/2866 RADIUS UDP envelope inspector. Only the
    /// conventional 1812/1813 ports and strict exact-length datagrams are
    /// recognized. No shared-secret, Response Authenticator, Message-Authenticator,
    /// credential, authorization or Access-Accept authenticity is verified.
    /// Authenticator and attribute contents are never retained or exposed.
    /// </summary>
    public static class RadiusPacketInspector
    {
        public static bool TryInspect(ReadOnlySpan<byte> datagram,
            ushort sourcePort, ushort destinationPort,
            bool verifiedCompleteUdpPayload, out RadiusPacketObservation observation)
        {
            observation = default;
            if (!verifiedCompleteUdpPayload || datagram.Length is < 20 or > 4096)
                return false;

            byte code = datagram[0];
            bool authentication = code is 1 or 2 or 3 or 11;
            bool accounting = code is 4 or 5;
            if ((!authentication && !accounting)
                || (authentication && sourcePort != 1812 && destinationPort != 1812)
                || (accounting && sourcePort != 1813 && destinationPort != 1813))
                return false;

            int declaredLength = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(2, 2));
            if (declaredLength != datagram.Length)
                return false; // Strict profile; RFC 2865 permits trailing UDP padding.

            int count = 0;
            bool hasMessageAuthenticator = false;
            for (int offset = 20; offset < datagram.Length;)
            {
                if (datagram.Length - offset < 2 || ++count > 128)
                    return false;
                byte type = datagram[offset];
                int attributeLength = datagram[offset + 1];
                if (type == 0 || attributeLength < 2
                    || attributeLength > datagram.Length - offset)
                    return false;
                if (type == 80)
                {
                    if (hasMessageAuthenticator || attributeLength != 18)
                        return false;
                    hasMessageAuthenticator = true; // HMAC NOT verified.
                }
                offset += attributeLength;
            }

            observation = new RadiusPacketObservation(code, count,
                hasMessageAuthenticator, datagram.Length);
            return true;
        }
    }

    public readonly record struct RadiusPacketObservation(
        byte Code, int AttributeCount, bool HasMessageAuthenticatorAttribute,
        int DatagramLength);
}
