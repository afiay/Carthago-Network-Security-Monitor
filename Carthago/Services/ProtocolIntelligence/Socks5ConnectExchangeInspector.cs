// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Bounded SOCKS5 client/server exchange framing prerequisite for R513.
    /// Caller must independently attest complete plaintext, bidirectional, same-session
    /// messages. A SOCKS5 CONNECT exchange does not prove SSH dynamic forwarding.
    /// </summary>
    public static class Socks5ConnectExchangeInspector
    {
        public static bool TryInspect(
            ReadOnlySpan<byte> greeting, ReadOnlySpan<byte> methodSelection,
            ReadOnlySpan<byte> request, ReadOnlySpan<byte> response,
            bool completePlaintextSameSession, out Socks5ConnectObservation observation)
        {
            observation = default;
            if (!completePlaintextSameSession || greeting.Length < 3 || greeting.Length > 257
                || greeting[0] != 5 || greeting[1] == 0 || greeting.Length != greeting[1] + 2
                || methodSelection.Length != 2 || methodSelection[0] != 5
                || methodSelection[1] != 0 || request.Length > 262 || response.Length > 262)
                return false;
            bool noAuthOffered = false;
            for (int i = 2; i < greeting.Length; i++)
                if (greeting[i] == 0) noAuthOffered = true;
            if (!noAuthOffered) return false;
            if (!TryAddressFrame(request, true, out byte requestType)
                || !TryAddressFrame(response, false, out byte responseType)
                || requestType != responseType)
                return false;
            observation = new Socks5ConnectObservation(response[1] == 0, requestType);
            return true;
        }

        private static bool TryAddressFrame(ReadOnlySpan<byte> frame, bool request, out byte type)
        {
            type = 0;
            if (frame.Length < 10 || frame[0] != 5 || frame[2] != 0) return false;
            if (request ? frame[1] != 1 : frame[1] > 8) return false;
            type = frame[3];
            int addressLength;
            switch (type)
            {
                case 1: addressLength = 4; break;
                case 4: addressLength = 16; break;
                case 3:
                    if (frame.Length < 7 || frame[4] == 0) return false;
                    addressLength = 1 + frame[4];
                    break;
                default: return false;
            }
            return frame.Length == 4 + (type == 3 ? 0 : 0) + addressLength + 2;
        }
    }

    public readonly record struct Socks5ConnectObservation(bool ServerAccepted, byte AddressType);
}
