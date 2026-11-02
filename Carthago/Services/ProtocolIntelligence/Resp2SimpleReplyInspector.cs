// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Bounded, single-frame RESP2 simple status/error reply classifier.
    /// This is a wire-shape observation, not an authenticated Redis server outcome.
    /// It never retains error text or any request/response payload.
    /// The caller must independently establish the TCP flow and reply boundary.
    /// </summary>
    public static class Resp2SimpleReplyInspector
    {
        private const int MaxReplyBytes = 256;

        public static bool TryInspect(ReadOnlySpan<byte> reply, out Resp2SimpleReplyKind kind)
        {
            kind = Resp2SimpleReplyKind.Unknown;
            if (reply.Length is < 5 or > MaxReplyBytes
                || reply[^2] != (byte)'\r' || reply[^1] != (byte)'\n')
                return false;

            if (reply.SequenceEqual("+OK\r\n"u8))
            {
                kind = Resp2SimpleReplyKind.Ok;
                return true;
            }

            // Redis errors have an ASCII '-' prefix and a single CRLF-delimited
            // line; verify the full frame, but never retain the error message.
            if (reply[0] != (byte)'-' || reply.Length < 7)
                return false;

            for (int i = 1; i < reply.Length - 2; i++)
                if (reply[i] is < 0x20 or > 0x7e)
                    return false;

            kind = Resp2SimpleReplyKind.Error;
            return true;
        }
    }

    public enum Resp2SimpleReplyKind
    {
        Unknown = 0,
        Ok,
        Error
    }
}
