// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Couchbase-compatible Memcached binary KV envelope (classic/flexible).
    /// Magic alone also matches generic Memcached: a trusted Couchbase endpoint
    /// and a complete plaintext TCP frame are mandatory caller preconditions.
    /// No keys, values, auth tokens, opaque IDs, CAS, bucket names or frame data
    /// are retained. Claimed response status is not an authenticated outcome.
    /// </summary>
    public static class CouchbaseKvEnvelopeInspector
    {
        private const int HeaderLength = 24;
        private const int MaximumBodyLength = 16 * 1024;
        private const int MaximumFrameInfoItems = 32;

        public static bool TryInspect(ReadOnlySpan<byte> frame,
            bool verifiedCompletePlaintextFrame, bool trustedCouchbaseEndpoint,
            out CouchbaseKvObservation observation)
        {
            observation = default;
            if (!verifiedCompletePlaintextFrame || !trustedCouchbaseEndpoint
                || frame.Length is < HeaderLength or > HeaderLength + MaximumBodyLength)
                return false;

            byte magic = frame[0];
            bool flexible = magic is 0x08 or 0x18;
            bool isResponse = magic is 0x81 or 0x18;
            if (magic is not (0x80 or 0x81 or 0x08 or 0x18))
                return false;

            byte opcode = frame[1];
            if (!IsRecognizedOpcode(opcode) || (frame[5] & 0xf8) != 0)
                return false;

            int framingLength = flexible ? frame[2] : 0;
            int keyLength = flexible ? frame[3]
                : BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(2, 2));
            int extrasLength = frame[4];
            uint bodyLength = BinaryPrimitives.ReadUInt32BigEndian(frame.Slice(8, 4));
            if (bodyLength != (uint)(frame.Length - HeaderLength)
                || framingLength + extrasLength + keyLength > bodyLength)
                return false;

            if (flexible && !ValidateFrameInfo(frame.Slice(HeaderLength, framingLength)))
                return false;

            int valueLength = (int)bodyLength - framingLength - extrasLength - keyLength;
            // A small strict subset of request-body semantics, not a KV decoder.
            if (!isResponse && ((opcode == 0x00 && (keyLength == 0 || extrasLength != 0 || valueLength != 0))
                || (opcode == 0x01 && (keyLength == 0 || extrasLength != 8))
                || (opcode == 0x04 && (keyLength == 0 || extrasLength != 0 || valueLength != 0))))
                return false;

            ushort? claimedStatus = isResponse
                ? BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(6, 2))
                : null;
            observation = new CouchbaseKvObservation(
                opcode, isResponse, flexible, keyLength, valueLength,
                frame.Length, claimedStatus);
            return true;
        }

        private static bool ValidateFrameInfo(ReadOnlySpan<byte> info)
        {
            int cursor = 0, count = 0;
            while (cursor < info.Length)
            {
                if (++count > MaximumFrameInfoItems)
                    return false;
                byte header = info[cursor++];
                int id = header >> 4, length = header & 0x0f;
                if (id == 15)
                {
                    if (cursor == info.Length) return false;
                    id += info[cursor++];
                }
                if (length == 15)
                {
                    if (cursor == info.Length) return false;
                    length += info[cursor++];
                }
                if (length > info.Length - cursor)
                    return false;
                cursor += length;
            }
            return true;
        }

        private static bool IsRecognizedOpcode(byte opcode)
            => opcode is 0x00 or 0x01 or 0x04 or 0x08 or 0x1f
                or 0x20 or 0x21 or 0x22 or 0x50 or 0x51 or 0x89;
    }

    public readonly record struct CouchbaseKvObservation(
        byte Opcode, bool IsResponse, bool FlexibleFraming, int KeyLength,
        int ValueLength, int FrameLength, ushort? ClaimedResponseStatus);
}