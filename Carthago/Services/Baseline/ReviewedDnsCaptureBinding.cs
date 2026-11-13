// SPDX-License-Identifier: MIT
using System;
using System.Security.Cryptography;

namespace Carthago.Services.Baseline
{
    // Byte integrity only. Neither a matching digest nor a scope establishes
    // authenticated capture provenance, benign review, or live eligibility.
    internal static class ReviewedDnsCaptureBinding
    {
        internal static bool Matches(ReadOnlySpan<byte> capture, string expectedSha256)
        {
            if (capture.IsEmpty || expectedSha256 == null || expectedSha256.Length != 64)
                return false;
            byte[] expected;
            try { expected = Convert.FromHexString(expectedSha256); }
            catch (FormatException) { return false; }
            return CryptographicOperations.FixedTimeEquals(SHA256.HashData(capture), expected);
        }
    }
}
