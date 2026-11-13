// SPDX-License-Identifier: MIT
using System;
using System.Security.Cryptography;

namespace Carthago.Services.Baseline
{
    // Offline signature prerequisite only. The public key must be provisioned
    // independently of the capture supplier. No live writer consumes this result.
    internal static class ReviewedDnsReviewSignature
    {
        internal static bool Matches(ReadOnlySpan<byte> manifest,
            ReadOnlySpan<byte> signature, ReadOnlySpan<byte> trustedPublicKey)
        {
            if (manifest.IsEmpty || manifest.Length > 16384 ||
                signature.Length != 64 || trustedPublicKey.IsEmpty ||
                trustedPublicKey.Length > 512) return false;
            try
            {
                using var key = ECDsa.Create();
                key.ImportSubjectPublicKeyInfo(trustedPublicKey, out int read);
                if (read != trustedPublicKey.Length) return false;
                var parameters = key.ExportParameters(false);
                if (parameters.Curve.Oid.Value != "1.2.840.10045.3.1.7")
                    return false;
                return key.VerifyData(manifest, signature, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            catch (CryptographicException) { return false; }
            catch (ArgumentException) { return false; }
        }
    }
}
