// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Strict single Modbus/TCP Read Device Identification (MEI 0x0E) request
    /// evidence boundary for R473. This does not establish authorization or
    /// enumeration success; the corresponding response must be correlated.
    /// </summary>
    public static class ModbusDeviceIdentificationRequestInspector
    {
        public static bool TryInspect(ReadOnlySpan<byte> frame, bool completeTcpAdu,
            out ModbusDeviceIdentificationRequest observation)
        {
            observation = default;
            // MBAP: transaction(2), protocol(2), length(2), unit(1).
            // PDU: function 0x2B, MEI 0x0E, read-code, object-id.
            if (!completeTcpAdu || frame.Length != 11 || frame[2] != 0 ||
                frame[3] != 0 || frame[4] != 0 || frame[5] != 5 ||
                frame[7] != 0x2B || frame[8] != 0x0E)
                return false;
            byte readCode = frame[9];
            if (readCode < 1 || readCode > 4)
                return false;
            // Basic/regular/extended access starts at object 0; specific access
            // permits any object ID. No success inference from request alone.
            if (readCode != 4 && frame[10] != 0)
                return false;
            observation = new ModbusDeviceIdentificationRequest(
                (ushort)((frame[0] << 8) | frame[1]), frame[6], readCode, frame[10]);
            return true;
        }
    }

    public readonly record struct ModbusDeviceIdentificationRequest(
        ushort TransactionId, byte UnitId, byte ReadCode, byte ObjectId);
}
