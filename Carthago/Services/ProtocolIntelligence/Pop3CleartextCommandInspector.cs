// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Strict isolated POP3 client command inspector for R316 prerequisites.
    /// The caller must independently attest complete application line framing
    /// and plaintext transport; packet port and Info are never evidence.
    /// Never returns, stores or logs USER/PASS argument bytes.
    /// A PASS command alone does not establish a credential was accepted.
    /// </summary>
    public static class Pop3CleartextCommandInspector
    {
        public static bool TryInspect(ReadOnlySpan<byte> completeLine,
            bool verifiedCompleteLine, bool verifiedPlaintextTransport,
            out Pop3CredentialCommandObservation observation)
        {
            observation = default;
            if (!verifiedCompleteLine || !verifiedPlaintextTransport ||
                completeLine.Length is < 7 or > 512 ||
                completeLine[^2] != 13 || completeLine[^1] != 10)
                return false;

            var command = completeLine.Slice(0, 4);
            bool user = IsCommand(command, "USER");
            bool pass = IsCommand(command, "PASS");
            if (!user && !pass || completeLine[4] != (byte)' ')
                return false;

            // Exactly one nonempty argument, ASCII printable and no embedded
            // control characters or extra lines. No argument material escapes.
            int length = completeLine.Length - 7;
            if (length is < 1 or > 505)
                return false;
            for (int i = 5; i < completeLine.Length - 2; i++)
                if (completeLine[i] < 33 || completeLine[i] > 126)
                    return false;

            observation = new Pop3CredentialCommandObservation(
                user ? Pop3CredentialCommandKind.User : Pop3CredentialCommandKind.Pass);
            return true;
        }

        private static bool IsCommand(ReadOnlySpan<byte> actual, string expected)
        {
            if (actual.Length != expected.Length) return false;
            for (int i = 0; i < actual.Length; i++)
                if (actual[i] != (byte)expected[i]) return false;
            return true;
        }
    }

    public enum Pop3CredentialCommandKind { User, Pass }

    public readonly record struct Pop3CredentialCommandObservation(
        Pop3CredentialCommandKind Kind);
}
