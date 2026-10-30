// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Strict, bounded RESP2 array-of-bulk-strings client-command framing.
    /// Requires caller-attested plaintext command boundary and direction.
    /// Returns only a fixed command family and argument count; never keys,
    /// credentials, Lua, RESTORE payloads, values, or server outcomes.
    /// ISOLATED: no TCP reassembly or capture registration.
    /// </summary>
    public static class Resp2CommandInspector
    {
        private const int MaxInputBytes = 8_192;
        private const int MaxArrayElements = 16;

        public static bool TryInspect(
            ReadOnlySpan<byte> bytes,
            bool verifiedPlaintextClientCommandBoundary,
            out Resp2CommandObservation observation)
        {
            observation = default;
            if (!verifiedPlaintextClientCommandBoundary || bytes.Length < 11
                || bytes.Length > MaxInputBytes)
                return false;

            int cursor = 0;
            if (!TryReadLengthLine(bytes, ref cursor, (byte)'*',
                    MaxArrayElements, out int elementCount) || elementCount < 1)
                return false;

            Resp2CommandKind command = default;
            for (int index = 0; index < elementCount; index++)
            {
                if (!TryReadLengthLine(bytes, ref cursor, (byte)'$',
                        MaxInputBytes, out int dataLength)
                    || dataLength > bytes.Length - cursor - 2)
                    return false;

                if (index == 0)
                {
                    command = ClassifyCommand(bytes.Slice(cursor, dataLength));
                    if (command == Resp2CommandKind.Unknown)
                        return false;
                }

                cursor += dataLength;
                if (cursor + 2 > bytes.Length || bytes[cursor] != '\r'
                    || bytes[cursor + 1] != '\n')
                    return false;
                cursor += 2;
            }

            observation = new(command, elementCount - 1, cursor);
            return true;
        }

        private static bool TryReadLengthLine(
            ReadOnlySpan<byte> bytes, ref int cursor, byte marker,
            int maximum, out int length)
        {
            length = 0;
            if (cursor >= bytes.Length || bytes[cursor++] != marker)
                return false;

            int digits = 0;
            int firstDigit = -1;
            while (cursor < bytes.Length && bytes[cursor] != '\r')
            {
                byte digit = bytes[cursor++];
                if (digit < '0' || digit > '9' || ++digits > 5)
                    return false;
                if (firstDigit < 0)
                    firstDigit = digit;
                if (digits > 1 && firstDigit == '0')
                    return false;
                length = length * 10 + digit - '0';
                if (length > maximum)
                    return false;
            }

            if (digits == 0 || cursor + 1 >= bytes.Length
                || bytes[cursor] != '\r' || bytes[cursor + 1] != '\n')
                return false;
            cursor += 2;
            return true;
        }

        private static Resp2CommandKind ClassifyCommand(ReadOnlySpan<byte> name)
        {
            if (AsciiEqualsIgnoreCase(name, "PING"u8)) return Resp2CommandKind.Ping;
            if (AsciiEqualsIgnoreCase(name, "GET"u8)) return Resp2CommandKind.Get;
            if (AsciiEqualsIgnoreCase(name, "SET"u8)) return Resp2CommandKind.Set;
            if (AsciiEqualsIgnoreCase(name, "AUTH"u8)) return Resp2CommandKind.Auth;
            if (AsciiEqualsIgnoreCase(name, "CONFIG"u8)) return Resp2CommandKind.Config;
            if (AsciiEqualsIgnoreCase(name, "EVAL"u8)) return Resp2CommandKind.Eval;
            if (AsciiEqualsIgnoreCase(name, "RESTORE"u8)) return Resp2CommandKind.Restore;
            if (AsciiEqualsIgnoreCase(name, "FLUSHALL"u8)) return Resp2CommandKind.FlushAll;
            if (AsciiEqualsIgnoreCase(name, "ACL"u8)) return Resp2CommandKind.Acl;
            if (AsciiEqualsIgnoreCase(name, "CLIENT"u8)) return Resp2CommandKind.Client;
            if (AsciiEqualsIgnoreCase(name, "HELLO"u8)) return Resp2CommandKind.Hello;
            if (AsciiEqualsIgnoreCase(name, "PUBLISH"u8)) return Resp2CommandKind.Publish;
            if (AsciiEqualsIgnoreCase(name, "SUBSCRIBE"u8)) return Resp2CommandKind.Subscribe;
            return Resp2CommandKind.Unknown;
        }

        private static bool AsciiEqualsIgnoreCase(
            ReadOnlySpan<byte> candidate, ReadOnlySpan<byte> expectedUppercase)
        {
            if (candidate.Length != expectedUppercase.Length)
                return false;
            for (int i = 0; i < candidate.Length; i++)
            {
                byte value = candidate[i];
                if (value >= 'a' && value <= 'z')
                    value = (byte)(value - ('a' - 'A'));
                if (value != expectedUppercase[i])
                    return false;
            }
            return true;
        }
    }

    public enum Resp2CommandKind
    {
        Unknown = 0,
        Ping,
        Get,
        Set,
        Auth,
        Config,
        Eval,
        Restore,
        FlushAll,
        Acl,
        Client,
        Hello,
        Publish,
        Subscribe
    }

    /// <summary>Untrusted request shape only; not authenticated command execution.</summary>
    public readonly record struct Resp2CommandObservation(
        Resp2CommandKind Command,
        int ArgumentCount,
        int BytesConsumed);
}
