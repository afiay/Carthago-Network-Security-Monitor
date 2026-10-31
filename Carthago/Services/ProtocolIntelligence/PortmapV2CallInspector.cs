// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// RFC 1831/1833 ONC RPC portmapper v2 CALL envelope, procedures 0-4.
    /// Requires a complete plaintext RPC message supplied by a trusted UDP
    /// datagram or TCP record-boundary adapter. Does not verify RPC credentials,
    /// server responses, mapping changes, or authorization. No XID/auth bytes kept.
    /// </summary>
    public static class PortmapV2CallInspector
    {
        private const int MaximumMessageLength = 2048;
        private const int MaximumAuthBytes = 400;

        public static bool TryInspect(ReadOnlySpan<byte> message,
            PortmapTransport transport, bool verifiedCompletePlaintextCall,
            out PortmapCallObservation observation)
        {
            observation = default;
            if (!verifiedCompletePlaintextCall
                || transport is not (PortmapTransport.Udp or PortmapTransport.Tcp)
                || message.Length is < 40 or > MaximumMessageLength)
                return false;

            // RPC v2 call header: xid, CALL, rpcvers, prog, vers, proc.
            if (Read32(message, 4) != 0 || Read32(message, 8) != 2
                || Read32(message, 12) != 100000 || Read32(message, 16) != 2)
                return false;

            uint procedure = Read32(message, 20);
            if (procedure > 4) // CALLIT (5) needs separate opaque-XDR validation.
                return false;

            int cursor = 24;
            if (!SkipOpaqueAuth(message, ref cursor)
                || !SkipOpaqueAuth(message, ref cursor))
                return false;

            uint program = 0, version = 0, protocol = 0, port = 0;
            if (procedure is 1 or 2 or 3)
            {
                if (message.Length - cursor != 16)
                    return false;
                program = Read32(message, cursor);
                version = Read32(message, cursor + 4);
                protocol = Read32(message, cursor + 8);
                port = Read32(message, cursor + 12);
                if (program == 0 || port > 65535)
                    return false;
                if ((procedure is 1 or 3) && (protocol is not (6 or 17)))
                    return false;
                if (procedure == 1 && port == 0)
                    return false;
                // UNSET ignores protocol/port per RFC 1833.
            }
            else if (cursor != message.Length)
                return false;

            observation = new PortmapCallObservation(
                (byte)procedure, program, version, protocol, (ushort)port, message.Length);
            return true;
        }

        private static bool SkipOpaqueAuth(ReadOnlySpan<byte> bytes, ref int cursor)
        {
            if (bytes.Length - cursor < 8)
                return false;
            // Auth flavor is not an authenticity assertion.
            uint length = Read32(bytes, cursor + 4);
            cursor += 8;
            if (length > MaximumAuthBytes)
                return false;
            int padded = ((int)length + 3) & ~3;
            if (padded > bytes.Length - cursor)
                return false;
            for (int i = (int)length; i < padded; i++)
                if (bytes[cursor + i] != 0)
                    return false;
            cursor += padded;
            return true;
        }

        private static uint Read32(ReadOnlySpan<byte> bytes, int offset)
            => BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(offset, 4));
    }

    public enum PortmapTransport : byte
    {
        Unknown = 0,
        Udp = 1,
        Tcp = 2
    }

    public readonly record struct PortmapCallObservation(
        byte Procedure, uint TargetProgram, uint TargetVersion,
        uint RequestedTransportProtocol, ushort RequestedPort, int MessageLength);
}