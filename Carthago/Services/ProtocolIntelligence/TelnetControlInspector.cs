// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// RFC 854 Telnet IAC control-token envelope only. Caller must attest that
    /// bytes are a complete, token-aligned contiguous TCP control sequence.
    /// Never inspects or retains terminal data, credentials or subnegotiation values.
    /// Not connected to capture and not proof of a Telnet session or intrusion.
    /// </summary>
    public static class TelnetControlInspector
    {
        public static bool TryInspect(ReadOnlySpan<byte> bytes,
            bool verifiedAlignedContiguousTcpControlBoundary,
            out TelnetControlObservation observation)
        {
            observation = default;
            if (!verifiedAlignedContiguousTcpControlBoundary || bytes.Length is < 3 or > 512
                || bytes[0] != 255)
                return false;

            byte command = bytes[1];
            if (command is >= 251 and <= 254)
            {
                if (bytes.Length != 3)
                    return false;
                observation = new TelnetControlObservation((TelnetControlKind)command, bytes[2], 3);
                return true;
            }

            if (command != 250 || bytes.Length < 5)
                return false;

            // IAC SB option ... IAC SE. Escaped IAC IAC is data, not a terminator.
            for (int index = 3; index < bytes.Length; index++)
            {
                if (bytes[index] != 255)
                    continue;
                if (index + 1 >= bytes.Length)
                    return false;
                byte next = bytes[++index];
                if (next == 255)
                    continue;
                if (next != 240 || index != bytes.Length - 1)
                    return false;
                observation = new TelnetControlObservation(
                    TelnetControlKind.Subnegotiation, bytes[2], bytes.Length);
                return true;
            }
            return false;
        }
    }

    public enum TelnetControlKind : byte
    {
        Subnegotiation = 250,
        Will = 251,
        Wont = 252,
        Do = 253,
        Dont = 254
    }

    public readonly record struct TelnetControlObservation(
        TelnetControlKind Kind, byte Option, int FrameLength);
}
