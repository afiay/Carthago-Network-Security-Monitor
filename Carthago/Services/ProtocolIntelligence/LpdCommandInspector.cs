// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Source-only RFC 1179 top-level command envelope inspector.
    /// The caller must attest a complete first TCP command line on a new
    /// client-to-server connection. This does not inspect job subcommands,
    /// validate authorization, track print jobs, or prove server outcomes.
    /// No queue, user, job identifier or payload text leaves the inspector.
    /// </summary>
    public static class LpdCommandInspector
    {
        private const int MaximumCommandLength = 256;
        private const int MaximumQueueLength = 64;
        private const int MaximumArgumentLength = 32;
        private const int MaximumArguments = 8;

        public static bool TryInspect(ReadOnlySpan<byte> command,
            ushort sourcePort, ushort destinationPort,
            bool verifiedCompleteInitialCommand, out LpdCommandObservation observation)
        {
            observation = default;
            if (!verifiedCompleteInitialCommand || destinationPort != 515 || sourcePort == 515
                || command.Length is < 3 or > MaximumCommandLength
                || command[^1] != (byte)'\n' || command[0] is < 1 or > 5)
                return false;

            var body = command.Slice(1, command.Length - 2);
            int separator = body.IndexOf((byte)' ');
            int queueLength = separator < 0 ? body.Length : separator;
            if (queueLength is < 1 or > MaximumQueueLength)
                return false;

            for (int i = 0; i < queueLength; i++)
            {
                byte b = body[i];
                if (!((b >= (byte)'a' && b <= (byte)'z')
                    || (b >= (byte)'A' && b <= (byte)'Z')
                    || (b >= (byte)'0' && b <= (byte)'9')
                    || b is (byte)'_' or (byte)'-' or (byte)'.'))
                    return false;
            }

            int argumentCount = 0;
            if (separator >= 0)
            {
                if (command[0] is 1 or 2)
                    return false;
                int offset = separator + 1;
                while (offset < body.Length)
                {
                    int nextSpace = body.Slice(offset).IndexOf((byte)' ');
                    int tokenLength = nextSpace < 0 ? body.Length - offset : nextSpace;
                    if (tokenLength is < 1 or > MaximumArgumentLength
                        || ++argumentCount > MaximumArguments)
                        return false;
                    for (int i = 0; i < tokenLength; i++)
                        if (body[offset + i] is < 33 or > 126)
                            return false;
                    offset += tokenLength;
                    if (offset == body.Length)
                        break;
                    offset++; // Skip exactly one ASCII space.
                    if (offset == body.Length)
                        return false;
                }
                if (argumentCount == 0)
                    return false;
            }

            // RFC 1179 Remove jobs requires an agent name.
            if (command[0] == 5 && argumentCount == 0)
                return false;

            observation = new LpdCommandObservation(
                (LpdCommandKind)command[0], queueLength, argumentCount, command.Length);
            return true;
        }
    }

    public enum LpdCommandKind : byte
    {
        PrintWaiting = 1,
        ReceiveJob = 2,
        QueueShort = 3,
        QueueLong = 4,
        RemoveJobs = 5
    }

    public readonly record struct LpdCommandObservation(
        LpdCommandKind CommandKind, int QueueNameLength, int ArgumentCount, int CommandLength);
}
