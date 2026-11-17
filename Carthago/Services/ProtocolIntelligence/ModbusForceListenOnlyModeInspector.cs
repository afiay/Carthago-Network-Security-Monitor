// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Exact Modbus/TCP request-only witness for diagnostics Force Listen Only Mode.
    /// The capture pipeline must independently verify TCP session, full segment
    /// framing, provenance, direction and absence of TLS. No server outcome follows
    /// from a function-08/subfunction-04 request.
    /// </summary>
    internal static class ModbusForceListenOnlyModeInspector
    {
        internal static bool TryInspect(ReadOnlySpan<byte> payload)
            => payload.Length == 12
               && BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2, 2)) == 0
               && BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(4, 2)) == 6
               && payload[6] is >= 1 and <= 247
               && payload[7] == 0x08
               && BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(8, 2)) == 0x0004
               && BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(10, 2)) == 0;
    }
}
