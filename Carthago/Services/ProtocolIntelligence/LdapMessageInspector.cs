// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Strict, bounded LDAPv3 BER envelope inspection at a caller-attested
    /// plaintext LDAPMessage boundary. Never decodes credentials, DNs,
    /// attributes, SASL, StartTLS, or authentication outcomes.
    /// ISOLATED: not connected to PacketHandler or a trusted stream producer.
    /// </summary>
    public static class LdapMessageInspector
    {
        private const int MaxEnvelopeLength = 65_535;
        private const int MaxInputBytes = MaxEnvelopeLength + 4;

        public static bool TryInspect(
            ReadOnlySpan<byte> bytes,
            bool verifiedPlaintextMessageBoundary,
            out LdapMessageObservation observation)
        {
            observation = default;
            if (!verifiedPlaintextMessageBoundary || bytes.Length < 7 || bytes.Length > MaxInputBytes)
                return false;

            int cursor = 0;
            if (!TryReadTlv(bytes, ref cursor, bytes.Length, out byte outerTag,
                    out int messageStart, out int messageLength)
                || outerTag != 0x30 || messageLength < 5)
                return false;

            int innerCursor = messageStart;
            int innerEnd = messageStart + messageLength;
            if (!TryReadTlv(bytes, ref innerCursor, innerEnd, out byte idTag,
                    out int idStart, out int idLength)
                || idTag != 0x02 || idLength is < 1 or > 4)
                return false;

            // BER INTEGER must be non-negative, minimal and fit LDAP maxInt.
            if ((bytes[idStart] & 0x80) != 0
                || (idLength > 1 && bytes[idStart] == 0
                    && (bytes[idStart + 1] & 0x80) == 0))
                return false;

            int messageId = 0;
            for (int i = 0; i < idLength; i++)
                messageId = (messageId << 8) | bytes[idStart + i];

            if (!TryReadTlv(bytes, ref innerCursor, innerEnd, out byte operationTag,
                    out _, out int operationLength)
                || !IsSupportedOperation(operationTag, operationLength)
                || (messageId == 0 && operationTag != 0x78))
                return false;

            bool hasControls = false;
            if (innerCursor < innerEnd)
            {
                if (!TryReadTlv(bytes, ref innerCursor, innerEnd, out byte controlsTag,
                        out _, out _)
                    || controlsTag != 0xA0)
                    return false;
                hasControls = true;
            }

            if (innerCursor != innerEnd)
                return false;

            observation = new LdapMessageObservation(
                messageId, operationTag, cursor, hasControls);
            return true;
        }

        private static bool IsSupportedOperation(byte tag, int length)
        {
            return tag switch
            {
                0x42 => length == 0,                    // UnbindRequest
                0x50 => length is >= 1 and <= 4,       // AbandonRequest
                0x60 or 0x61 or 0x63 or 0x64 or 0x65
                    or 0x66 or 0x67 or 0x68 or 0x69
                    or 0x4A or 0x6B or 0x6C or 0x6D
                    or 0x6E or 0x6F or 0x73 or 0x77
                    or 0x78 or 0x79 => length > 0,
                _ => false
            };
        }

        // Definite-length, minimally encoded BER only. No recursive decoding
        // and no indefinite/oversized allocations from untrusted input.
        private static bool TryReadTlv(
            ReadOnlySpan<byte> bytes, ref int cursor, int limit,
            out byte tag, out int valueStart, out int valueLength)
        {
            tag = 0;
            valueStart = 0;
            valueLength = 0;
            if (limit > bytes.Length || cursor < 0 || cursor >= limit)
                return false;

            tag = bytes[cursor++];
            if (cursor >= limit)
                return false;

            int lengthOctet = bytes[cursor++];
            if ((lengthOctet & 0x80) == 0)
            {
                valueLength = lengthOctet;
            }
            else
            {
                int count = lengthOctet & 0x7F;
                if (count is < 1 or > 2 || count > limit - cursor
                    || bytes[cursor] == 0)
                    return false;

                for (int i = 0; i < count; i++)
                    valueLength = (valueLength << 8) | bytes[cursor++];

                if (valueLength < 128 || (count == 2 && valueLength <= 255))
                    return false;
            }

            if (valueLength > MaxEnvelopeLength || valueLength > limit - cursor)
                return false;

            valueStart = cursor;
            cursor += valueLength;
            return true;
        }
    }

    /// <summary>Untrusted LDAP message-shape metadata, not a directory action result.</summary>
    public readonly record struct LdapMessageObservation(
        int MessageId,
        byte OperationTag,
        int BytesConsumed,
        bool HasControls);
}
