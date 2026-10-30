// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Isolated OPC UA TCP connection-layer HEL/ACK/ERR message-shape inspector.
    /// Requires a trusted, complete, reassembled plaintext UACP message boundary.
    /// Does not parse secure-channel payloads, endpoint URLs, credentials or operations.
    /// </summary>
    public static class OpcUaConnectionInspector
    {
        private const int MaxMessageBytes = 8192;
        private const int MaxUrlBytes = 4095;

        public static bool TryInspect(ReadOnlySpan<byte> message,
            bool verifiedCompleteTcpMessageBoundary,
            out OpcUaConnectionObservation observation)
        {
            observation = default;
            if (!verifiedCompleteTcpMessageBoundary
                || message.Length < 8 || message.Length > MaxMessageBytes
                || message[3] != (byte)'F'
                || BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(4, 4)) != (uint)message.Length)
                return false;

            OpcUaConnectionKind kind;
            if (message[0] == (byte)'H' && message[1] == (byte)'E' && message[2] == (byte)'L')
            {
                if (message.Length < 32 || !BuffersPlausible(message))
                    return false;
                int urlLength = BinaryPrimitives.ReadInt32LittleEndian(message.Slice(28, 4));
                if (urlLength < 0 || urlLength > MaxUrlBytes || message.Length != 32 + urlLength)
                    return false;
                kind = OpcUaConnectionKind.Hello;
            }
            else if (message[0] == (byte)'A' && message[1] == (byte)'C' && message[2] == (byte)'K')
            {
                if (message.Length != 28 || !BuffersPlausible(message))
                    return false;
                kind = OpcUaConnectionKind.Acknowledge;
            }
            else if (message[0] == (byte)'E' && message[1] == (byte)'R' && message[2] == (byte)'R')
            {
                if (message.Length < 16)
                    return false;
                int reasonLength = BinaryPrimitives.ReadInt32LittleEndian(message.Slice(12, 4));
                if (reasonLength < -1 || reasonLength > 4096
                    || message.Length != 16 + Math.Max(0, reasonLength))
                    return false;
                kind = OpcUaConnectionKind.Error;
            }
            else
                return false; // OPN/MSG/CLO secure-channel and RHE are not decoded.

            // No endpoint URL, status text, node identifiers or body bytes retained.
            observation = new OpcUaConnectionObservation(kind, message.Length);
            return true;
        }

        private static bool BuffersPlausible(ReadOnlySpan<byte> message)
            => BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(12, 4)) >= 1024
               && BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(16, 4)) >= 1024;
    }

    public enum OpcUaConnectionKind : byte { Hello = 1, Acknowledge = 2, Error = 3 }

    /// <summary>Unauthenticated plaintext envelope metadata, not an OPC UA operation.</summary>
    public readonly record struct OpcUaConnectionObservation(OpcUaConnectionKind Kind, int MessageLength);
}