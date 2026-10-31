// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Apache Cassandra CQL native protocol v4, complete plaintext 9-byte-header
    /// frame envelope only. Caller attests TCP reassembly, exact frame boundary,
    /// endpoint identity and absence of TLS; this class cannot verify the claim.
    /// Never parses or retains CQL, auth responses, trace IDs or stream IDs.
    /// v5 segmented envelopes and compressed body semantics are not supported.
    /// </summary>
    public static class CassandraCqlV4FrameInspector
    {
        private const int HeaderLength = 9;
        private const int MaximumFrameLength = 16 * 1024;

        public static bool TryInspect(ReadOnlySpan<byte> frame,
            bool verifiedCompletePlaintextFrame, out CassandraCqlV4Observation observation)
        {
            observation = default;
            if (!verifiedCompletePlaintextFrame
                || frame.Length is < HeaderLength or > MaximumFrameLength)
                return false;

            byte version = frame[0];
            if (version is not (0x04 or 0x84))
                return false;
            bool isResponse = (version & 0x80) != 0;
            byte flags = frame[1];
            byte opcode = frame[4];
            if ((flags & 0xf0) != 0
                || (isResponse ? !IsResponseOpcode(opcode) : !IsRequestOpcode(opcode)))
                return false;

            short stream = BinaryPrimitives.ReadInt16BigEndian(frame.Slice(2, 2));
            if ((!isResponse && stream < 0)
                || (isResponse && ((opcode == 0x0c && stream != -1)
                    || (opcode != 0x0c && stream < 0))))
                return false;

            uint bodyLength = BinaryPrimitives.ReadUInt32BigEndian(frame.Slice(5, 4));
            if (bodyLength != (uint)(frame.Length - HeaderLength))
                return false;

            bool compressed = (flags & 0x01) != 0;
            bool tracing = (flags & 0x02) != 0;
            bool customPayload = (flags & 0x04) != 0;
            bool warning = (flags & 0x08) != 0;
            if ((!isResponse && warning)
                || (customPayload && opcode is not (0x07 or 0x09 or 0x0a or 0x0d))
                || (opcode == 0x01 && compressed)
                || ((opcode is 0x02 or 0x05) && bodyLength != 0)
                || (opcode == 0x01 && bodyLength < 2))
                return false;

            observation = new CassandraCqlV4Observation(
                opcode, isResponse, compressed, tracing, customPayload,
                warning, frame.Length);
            return true;
        }

        private static bool IsRequestOpcode(byte opcode)
            => opcode is 0x01 or 0x05 or 0x07 or 0x09 or 0x0a or 0x0b or 0x0d or 0x0f;

        private static bool IsResponseOpcode(byte opcode)
            => opcode is 0x00 or 0x02 or 0x03 or 0x06 or 0x08 or 0x0c or 0x0e or 0x10;
    }

    public readonly record struct CassandraCqlV4Observation(
        byte Opcode, bool IsResponse, bool CompressedBodyOpaque,
        bool TracingFlag, bool CustomPayloadFlag, bool WarningFlag, int FrameLength);
}