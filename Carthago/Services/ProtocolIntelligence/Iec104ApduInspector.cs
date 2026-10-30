// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Bounded IEC 60870-5-104 APCI frame-shape inspector.
    /// Requires a complete trusted TCP APDU boundary, not an arbitrary segment.
    /// No command authorization, device-role attribution or action outcome.
    /// </summary>
    public static class Iec104ApduInspector
    {
        public static bool TryInspect(ReadOnlySpan<byte> apdu,
            bool verifiedCompleteTcpApduBoundary,
            out Iec104ApduObservation observation)
        {
            observation = default;
            if (!verifiedCompleteTcpApduBoundary || apdu.Length is < 6 or > 255
                || apdu[0] != 0x68 || apdu[1] < 4 || apdu[1] > 253
                || apdu.Length != apdu[1] + 2)
                return false;

            byte control = apdu[2];
            Iec104FrameKind kind;
            byte? asduType = null;
            if ((control & 1) == 0)
            {
                // I-frame must contain at least a six-byte ASDU header.
                if (apdu.Length < 12 || (apdu[4] & 1) != 0 || (apdu[7] & 0x7f) == 0)
                    return false;
                kind = Iec104FrameKind.Information;
                asduType = apdu[6];
            }
            else if (control == 0x01)
            {
                if (apdu.Length != 6 || apdu[3] != 0 || (apdu[4] & 1) != 0)
                    return false;
                kind = Iec104FrameKind.Supervisory;
            }
            else if (control is 0x07 or 0x0b or 0x13 or 0x23 or 0x43 or 0x83)
            {
                if (apdu.Length != 6 || apdu[3] != 0 || apdu[4] != 0 || apdu[5] != 0)
                    return false;
                kind = Iec104FrameKind.Unnumbered;
            }
            else
                return false;

            // ASDU type is an unauthenticated hint, not evidence of command execution.
            observation = new Iec104ApduObservation(kind, apdu.Length, asduType);
            return true;
        }
    }

    public enum Iec104FrameKind : byte { Information = 1, Supervisory = 2, Unnumbered = 3 }

    public readonly record struct Iec104ApduObservation(
        Iec104FrameKind Kind, int ApduLength, byte? AsduType);
}