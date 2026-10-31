// SPDX-License-Identifier: MIT
using System;
namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Isolated IEC 60870-5-101 FT1.2 serial link-frame observer.
    /// Requires an independently verified complete plaintext serial frame
    /// and configured link-address width. Not a TCP/IEC104 parser.
    /// No capture producer, authentication, ASDU decoding or alerts.
    /// </summary>
    public static class Iec101Ft12Inspector
    {
        public static bool TryInspect(ReadOnlySpan<byte> frame,
            bool verifiedCompletePlaintextSerialFrame, int linkAddressOctets,
            out Iec101Ft12Observation observation)
        {
            observation = default;
            if (!verifiedCompletePlaintextSerialFrame || linkAddressOctets is not (1 or 2)
                || frame.Length is < 1 or > 261) return false;
            if (frame.Length == 1)
            {
                var kind = frame[0] switch
                {
                    0xe5 => Iec101Ft12FrameKind.PositiveAcknowledgement,
                    0xa2 => Iec101Ft12FrameKind.NegativeAcknowledgement,
                    _ => Iec101Ft12FrameKind.None
                };
                if (kind == Iec101Ft12FrameKind.None) return false;
                observation = new(kind, 1, null, null);
                return true;
            }
            if (frame[0] == 0x10)
            {
                if (frame.Length != linkAddressOctets + 4 || frame[^1] != 0x16
                    || (frame[1] & 0x80) != 0
                    || !HasChecksum(frame, 1, linkAddressOctets + 1, frame[^2]))
                    return false;
                observation = new(Iec101Ft12FrameKind.Fixed, frame.Length,
                    (byte)(frame[1] & 0x0f), null);
                return true;
            }
            if (frame[0] != 0x68 || frame.Length < 6) return false;
            int length = frame[1];
            if (length < linkAddressOctets + 2 || frame[2] != length
                || frame[3] != 0x68 || frame.Length != length + 6
                || frame[^1] != 0x16 || (frame[4] & 0x80) != 0
                || !HasChecksum(frame, 4, length, frame[^2]))
                return false;
            byte asduType = frame[5 + linkAddressOctets];
            if (asduType == 0) return false;
            observation = new(Iec101Ft12FrameKind.Variable, frame.Length,
                (byte)(frame[4] & 0x0f), asduType);
            return true;
        }
        private static bool HasChecksum(ReadOnlySpan<byte> bytes, int start,
            int length, byte expected)
        {
            int sum = 0;
            for (int i = 0; i < length; i++) sum += bytes[start + i];
            return (byte)sum == expected;
        }
    }
    public enum Iec101Ft12FrameKind : byte
    {
        None, Fixed, Variable, PositiveAcknowledgement, NegativeAcknowledgement
    }
    /// <summary>No station address, serial identity, ASDU body or raw bytes retained.</summary>
    public readonly record struct Iec101Ft12Observation(
        Iec101Ft12FrameKind Kind, int FrameLength,
        byte? LinkFunctionCode, byte? AsduType);
}
