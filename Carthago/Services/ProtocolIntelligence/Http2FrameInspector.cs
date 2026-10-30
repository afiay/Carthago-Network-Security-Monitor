// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Inspects one complete HTTP/2 frame at a verified plaintext frame boundary.
    /// Never decodes HPACK, TLS ciphertext, request bodies, or stream outcomes.
    /// Not registered with PacketHandler: isolated source candidate only.
    /// </summary>
    public static class Http2FrameInspector
    {
        private const int FrameHeaderLength = 9;
        private const int MaxInspectedFramePayload = 16_384;
        private static ReadOnlySpan<byte> ClientPreface => "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8;

        public static bool TryInspect(
            ReadOnlySpan<byte> bytes,
            bool verifiedPlaintextContext,
            bool expectClientPreface,
            out Http2FrameObservation observation)
        {
            observation = default;
            // A port or ALPN hint alone must not be used as verified plaintext.
            if (!verifiedPlaintextContext)
                return false;

            int offset = 0;
            if (expectClientPreface)
            {
                if (bytes.Length < ClientPreface.Length + FrameHeaderLength
                    || !bytes.Slice(0, ClientPreface.Length).SequenceEqual(ClientPreface))
                    return false;
                offset = ClientPreface.Length;
            }

            if (bytes.Length - offset < FrameHeaderLength)
                return false;

            int length = (bytes[offset] << 16) | (bytes[offset + 1] << 8) | bytes[offset + 2];
            byte type = bytes[offset + 3];
            byte flags = bytes[offset + 4];
            uint rawStreamId = BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(offset + 5, 4));
            if (length > MaxInspectedFramePayload || (rawStreamId & 0x80000000u) != 0
                || length > bytes.Length - offset - FrameHeaderLength)
                return false;

            int streamId = (int)rawStreamId;
            // Recognize standard frames only. Extensions and incomplete frame
            // sequences need a separate, explicitly trusted stream adapter.
            bool valid = type switch
            {
                0 => streamId != 0,                         // DATA
                1 => streamId != 0,                         // HEADERS (HPACK opaque)
                2 => streamId != 0 && length == 5,          // PRIORITY
                3 => streamId != 0 && length == 4,          // RST_STREAM
                4 => streamId == 0 && length % 6 == 0
                    && ((flags & 0x01) == 0 || length == 0), // SETTINGS / ACK
                5 => streamId != 0 && length >= 4,          // PUSH_PROMISE
                6 => streamId == 0 && length == 8,          // PING
                7 => streamId == 0 && length >= 8,          // GOAWAY
                8 => length == 4,                           // WINDOW_UPDATE
                9 => streamId != 0,                         // CONTINUATION
                _ => false
            };
            if (!valid || (expectClientPreface && (type != 4 || streamId != 0)))
                return false;

            observation = new Http2FrameObservation(
                type, flags, streamId, length, offset + FrameHeaderLength + length,
                expectClientPreface);
            return true;
        }
    }

    /// <summary>Non-sensitive, single-frame shape only; not an HTTP request or exploit verdict.</summary>
    public readonly record struct Http2FrameObservation(
        byte FrameType,
        byte Flags,
        int StreamId,
        int FramePayloadLength,
        int BytesConsumed,
        bool ClientPrefaceObserved);
}
