// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Bounded PostgreSQL frontend startup/SSL/GSS request shape at a caller-attested
    /// plaintext connection-start boundary. Never returns usernames, database names,
    /// passwords, options, cancel keys or server/authentication outcomes.
    /// ISOLATED: no TCP reassembly, capture producer or runtime registration.
    /// </summary>
    public static class PostgresStartupInspector
    {
        private const int MaxInspectedBytes = 8_192;
        private const int MaxParameterPairs = 32;
        private const int MaxKeyBytes = 64;
        private const int MaxValueBytes = 2_048;
        private const int ProtocolV30 = 0x00030000;
        private const int SslRequestCode = 80877103;
        private const int GssRequestCode = 80877104;

        public static bool TryInspect(
            ReadOnlySpan<byte> bytes,
            bool verifiedPlaintextConnectionStart,
            out PostgresStartupObservation observation)
        {
            observation = default;
            if (!verifiedPlaintextConnectionStart || bytes.Length < 8
                || bytes.Length > MaxInspectedBytes)
                return false;

            int messageLength = BinaryPrimitives.ReadInt32BigEndian(bytes.Slice(0, 4));
            if (messageLength < 8 || messageLength > MaxInspectedBytes
                || messageLength > bytes.Length)
                return false;

            int requestCode = BinaryPrimitives.ReadInt32BigEndian(bytes.Slice(4, 4));
            if (messageLength == 8 && requestCode == SslRequestCode)
            {
                observation = new(PostgresStartupKind.SslRequest, 8, 0, false, false);
                return true;
            }
            if (messageLength == 8 && requestCode == GssRequestCode)
            {
                observation = new(PostgresStartupKind.GssEncryptionRequest, 8, 0, false, false);
                return true;
            }
            // Deliberately version 3.0 only: PostgreSQL 18 also defines 3.2.
            if (requestCode != ProtocolV30 || messageLength < 10
                || bytes[messageLength - 1] != 0)
                return false;

            int cursor = 8;
            int parameterPairs = 0;
            bool hasUser = false;
            bool hasDatabase = false;
            while (cursor < messageLength)
            {
                if (bytes[cursor] == 0)
                {
                    // The final empty key terminates the parameter list.
                    if (cursor != messageLength - 1 || parameterPairs == 0 || !hasUser)
                        return false;
                    observation = new(PostgresStartupKind.StartupV30, messageLength,
                        parameterPairs, hasUser, hasDatabase);
                    return true;
                }
                if (parameterPairs >= MaxParameterPairs)
                    return false;

                int keyEndOffset = bytes.Slice(cursor, messageLength - cursor).IndexOf((byte)0);
                if (keyEndOffset is < 1 or > MaxKeyBytes)
                    return false;
                ReadOnlySpan<byte> key = bytes.Slice(cursor, keyEndOffset);
                if (!IsBoundedAsciiKey(key))
                    return false;
                cursor += keyEndOffset + 1;

                if (cursor >= messageLength)
                    return false;
                int valueEndOffset = bytes.Slice(cursor, messageLength - cursor).IndexOf((byte)0);
                if (valueEndOffset < 0 || valueEndOffset > MaxValueBytes)
                    return false;
                // Values can be binary/UTF-8 and sensitive: only skip, never decode.
                cursor += valueEndOffset + 1;
                parameterPairs++;
                hasUser |= key.SequenceEqual("user"u8);
                hasDatabase |= key.SequenceEqual("database"u8);
            }
            return false;
        }

        private static bool IsBoundedAsciiKey(ReadOnlySpan<byte> key)
        {
            foreach (byte b in key)
            {
                if (!((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
                    || (b >= '0' && b <= '9') || b == (byte)'_'
                    || b == (byte)'.' || b == (byte)'-'))
                    return false;
            }
            return true;
        }
    }

    public enum PostgresStartupKind
    {
        StartupV30 = 1,
        SslRequest = 2,
        GssEncryptionRequest = 3
    }

    /// <summary>Untrusted framing observation, not a database login or exploit result.</summary>
    public readonly record struct PostgresStartupObservation(
        PostgresStartupKind Kind,
        int BytesConsumed,
        int ParameterPairs,
        bool HasUserParameter,
        bool HasDatabaseParameter);
}
