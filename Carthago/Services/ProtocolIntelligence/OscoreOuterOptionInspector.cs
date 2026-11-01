// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// RFC 7252 UDP CoAP outer-envelope / RFC 8613 OSCORE option shape only.
    /// Caller must attest a single complete, unfragmented, readable CoAP UDP
    /// datagram, endpoint context and trusted capture provenance.
    /// Does not decrypt, authenticate, detect replay, parse inner operations,
    /// retain identifiers, or establish a CVE exploit or server outcome.
    /// ISOLATED — NOT LIVE-CAPTURE INTEGRATED.
    /// </summary>
    public static class OscoreOuterOptionInspector
    {
        private const int MaximumDatagramBytes = 1152;
        private const int MaximumOptions = 64;
        private const int OscoreOptionNumber = 9;

        public static bool TryInspect(
            ReadOnlySpan<byte> datagram,
            bool verifiedCompleteUdpDatagram,
            bool verifiedUnfragmentedIpPacket,
            bool verifiedCoapUdpEndpoint,
            bool verifiedReadableCoapOuter,
            bool verifiedCaptureProvenance,
            out OscoreOuterObservation observation)
        {
            observation = default;
            if (!verifiedCompleteUdpDatagram || !verifiedUnfragmentedIpPacket ||
                !verifiedCoapUdpEndpoint || !verifiedReadableCoapOuter ||
                !verifiedCaptureProvenance ||
                datagram.Length < 7 || datagram.Length > MaximumDatagramBytes ||
                (datagram[0] >> 6) != 1 || datagram[1] == 0)
                return false;

            int tokenLength = datagram[0] & 0x0f;
            if (tokenLength > 8 || 4 + tokenLength >= datagram.Length)
                return false;

            int offset = 4 + tokenLength;
            int optionNumber = 0;
            int optionCount = 0;
            int partialIvLength = 0;
            bool found = false;
            bool hasKid = false;
            bool hasKidContext = false;
            int ciphertextLength = 0;

            while (offset < datagram.Length)
            {
                byte header = datagram[offset++];
                if (header == 0xff)
                {
                    // RFC 8613: OSCORE option without a payload is malformed.
                    if (offset >= datagram.Length || !found)
                        return false;

                    ciphertextLength = datagram.Length - offset;
                    observation = new OscoreOuterObservation(
                        datagram[1], partialIvLength, hasKid, hasKidContext,
                        ciphertextLength);
                    return true;
                }

                if (++optionCount > MaximumOptions ||
                    !TryReadExtended(datagram, ref offset, header >> 4, out int delta) ||
                    !TryReadExtended(datagram, ref offset, header & 0x0f, out int length) ||
                    delta > ushort.MaxValue - optionNumber ||
                    length > datagram.Length - offset)
                    return false;

                optionNumber += delta;
                ReadOnlySpan<byte> value = datagram.Slice(offset, length);
                offset += length;

                if (optionNumber != OscoreOptionNumber)
                    continue;

                if (found ||
                    !TryInspectOscoreOption(value, out partialIvLength,
                        out hasKid, out hasKidContext))
                    return false;

                found = true;
            }

            return false;
        }

        private static bool TryReadExtended(
            ReadOnlySpan<byte> bytes, ref int offset, int nibble, out int value)
        {
            value = 0;
            if (nibble < 13)
            {
                value = nibble;
                return true;
            }

            if (nibble == 13)
            {
                if (offset >= bytes.Length)
                    return false;

                value = 13 + bytes[offset++];
                return true;
            }

            if (nibble != 14 || bytes.Length - offset < 2)
                return false;

            value = 269 + (bytes[offset] << 8) + bytes[offset + 1];
            offset += 2;
            return true;
        }

        private static bool TryInspectOscoreOption(
            ReadOnlySpan<byte> value, out int partialIvLength,
            out bool hasKid, out bool hasKidContext)
        {
            partialIvLength = 0;
            hasKid = false;
            hasKidContext = false;

            // All-zero flags MUST be encoded as an empty option.
            if (value.IsEmpty)
                return true;

            byte flags = value[0];
            partialIvLength = flags & 0x07;
            hasKid = (flags & 0x08) != 0;
            hasKidContext = (flags & 0x10) != 0;
            if (flags == 0 || (flags & 0xe0) != 0 ||
                partialIvLength > 5 || value.Length - 1 < partialIvLength)
                return false;

            int offset = 1 + partialIvLength;
            if (hasKidContext)
            {
                if (offset >= value.Length)
                    return false;

                int contextLength = value[offset++];
                if (contextLength > value.Length - offset)
                    return false;

                offset += contextLength;
            }

            // A present but empty kid is legal (RFC 8613 §6.3 example 2).
            // Without the kid flag no trailing bytes are permitted.
            return hasKid || offset == value.Length;
        }
    }

    /// <summary>
    /// Privacy-safe, unverified outer-message shape; no sender ID, partial-IV
    /// value, kid, context, ciphertext, plaintext, authentication or replay claim.
    /// </summary>
    public readonly record struct OscoreOuterObservation(
        byte OuterCode,
        int PartialIvByteCount,
        bool HasKid,
        bool HasKidContext,
        int OpaquePayloadByteCount);
}
