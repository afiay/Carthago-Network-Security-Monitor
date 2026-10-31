// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Source-only, bounded EtherNet/IP encapsulation inspection (ODVA Volume 2).
    /// Caller must supply one complete plaintext message with verified TCP framing,
    /// direction and ports. No TCP reassembly, CIP object/path interpretation,
    /// authentication, authorization, alerting, logging or runtime registration.
    /// </summary>
    public static class CipEncapsulationInspector
    {
        private const int HeaderLength = 24;
        private const int MaximumMessageLength = 65535;

        public static bool TryInspect(ReadOnlySpan<byte> message, ushort sourcePort,
            ushort destinationPort, bool isTcp, bool isClientToServer,
            bool verifiedCompletePlaintextMessage, out CipEncapsulationObservation observation)
        {
            observation = default;
            if (!verifiedCompletePlaintextMessage || !isTcp
                || message.Length is < HeaderLength or > MaximumMessageLength
                || (isClientToServer
                    ? destinationPort != 44818 || sourcePort == 44818
                    : sourcePort != 44818 || destinationPort == 44818))
                return false;

            ushort command = BinaryPrimitives.ReadUInt16LittleEndian(message);
            ushort payloadLength = BinaryPrimitives.ReadUInt16LittleEndian(message.Slice(2, 2));
            uint session = BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(4, 4));
            uint status = BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(8, 4));
            uint options = BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(20, 4));
            if (payloadLength != message.Length - HeaderLength || status != 0 || options != 0)
                return false; // Conservative successful-envelope subset, not an outcome claim.

            CipEncapsulationCommand kind;
            switch (command)
            {
                case 0x0065: // RegisterSession, exact 4-byte version/options payload.
                    if (payloadLength != 4
                        || BinaryPrimitives.ReadUInt16LittleEndian(message.Slice(24, 2)) != 1
                        || BinaryPrimitives.ReadUInt16LittleEndian(message.Slice(26, 2)) != 0
                        || (isClientToServer ? session != 0 : session == 0))
                        return false;
                    kind = CipEncapsulationCommand.RegisterSession;
                    break;
                case 0x0066: // UnRegisterSession is request-only.
                    if (!isClientToServer || payloadLength != 0 || session == 0)
                        return false;
                    kind = CipEncapsulationCommand.UnregisterSession;
                    break;
                case 0x006f:
                case 0x0070:
                    if (session == 0 || !HasConservativeCpf(message.Slice(HeaderLength),
                        command == 0x006f))
                        return false;
                    kind = command == 0x006f
                        ? CipEncapsulationCommand.SendRequestReplyData
                        : CipEncapsulationCommand.SendUnitData;
                    break;
                default:
                    return false; // ListIdentity is already recognized by existing helper.
            }

            observation = new CipEncapsulationObservation(kind, message.Length,
                payloadLength, !isClientToServer);
            return true;
        }

        private static bool HasConservativeCpf(ReadOnlySpan<byte> payload, bool unconnected)
        {
            // Interface Handle (4), Timeout (2), ItemCount (2), two typed CPF items.
            if (payload.Length < 18
                || BinaryPrimitives.ReadUInt32LittleEndian(payload) != 0
                || BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(6, 2)) != 2)
                return false;

            int offset = 8;
            if (!TryReadItem(payload, ref offset, out ushort addressType,
                    out ushort addressLength)
                || (unconnected
                    ? addressType != 0 || addressLength != 0
                    : addressType != 0x00a1 || addressLength != 4))
                return false;

            if (!TryReadItem(payload, ref offset, out ushort dataType,
                    out ushort dataLength)
                || (unconnected ? dataType != 0x00b2 : dataType != 0x00b1)
                || dataLength < 2)
                return false;

            return offset == payload.Length; // Exactly one bounded complete CPF message.
        }

        private static bool TryReadItem(ReadOnlySpan<byte> payload, ref int offset,
            out ushort type, out ushort length)
        {
            type = 0;
            length = 0;
            if (payload.Length - offset < 4)
                return false;
            type = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(offset, 2));
            length = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(offset + 2, 2));
            offset += 4;
            if (length > payload.Length - offset)
                return false;
            offset += length;
            return true;
        }
    }

    public enum CipEncapsulationCommand : ushort
    {
        RegisterSession = 0x0065,
        UnregisterSession = 0x0066,
        SendRequestReplyData = 0x006f,
        SendUnitData = 0x0070
    }

    /// <summary>No session handle, sender context, object path or payload is retained.</summary>
    public readonly record struct CipEncapsulationObservation(
        CipEncapsulationCommand Command, int MessageLength, int PayloadLength, bool IsReply);
}
