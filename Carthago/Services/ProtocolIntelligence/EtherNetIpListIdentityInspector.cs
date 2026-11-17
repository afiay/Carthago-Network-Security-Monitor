// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Strict EtherNet/IP encapsulation ListIdentity request boundary for R488.
    /// Requires a complete, independently reassembled transport payload.
    /// A request is not a successful inventory response or unauthorized scan.
    /// </summary>
    public static class EtherNetIpListIdentityInspector
    {
        public static bool TryInspectRequest(ReadOnlySpan<byte> payload, bool completeTransportMessage,
            out EtherNetIpListIdentityRequest observation)
        {
            observation = default;
            // Encapsulation header: command(2), length(2), session(4), status(4),
            // sender context(8), options(4), all little-endian.
            if (!completeTransportMessage || payload.Length != 24)
                return false;
            if (BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(0, 2)) != 0x0063 ||
                BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(2, 2)) != 0 ||
                BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(4, 4)) != 0 ||
                BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(8, 4)) != 0 ||
                BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(20, 4)) != 0)
                return false;
            observation = new EtherNetIpListIdentityRequest(
                BinaryPrimitives.ReadUInt64LittleEndian(payload.Slice(12, 8)));
            return true;
        }
    }

    public readonly record struct EtherNetIpListIdentityRequest(ulong SenderContext);
}
