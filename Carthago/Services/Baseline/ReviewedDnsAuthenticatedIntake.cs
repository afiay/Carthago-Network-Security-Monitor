// SPDX-License-Identifier: MIT
using System;
using System.Security.Cryptography;

namespace Carthago.Services.Baseline
{
    // Construct only at the trusted configuration boundary, never from submission data.
    // No live writer consumes this offline candidate.
    internal sealed class ReviewedDnsAuthenticatedIntake
    {
        private readonly byte[] _reviewKey;

        internal ReviewedDnsAuthenticatedIntake(ReadOnlySpan<byte> provisionedReviewKey)
        {
            if (provisionedReviewKey.IsEmpty || provisionedReviewKey.Length > 512)
                throw new ArgumentException("Invalid review key size.", nameof(provisionedReviewKey));
            _reviewKey = provisionedReviewKey.ToArray();
        }

        internal bool Matches(ReadOnlySpan<byte> manifest, ReadOnlySpan<byte> signature,
            ReadOnlySpan<byte> capture, string source, string sensor, string interfaceId, string network)
        {
            if (manifest.IsEmpty || manifest.Length > 16384 || signature.Length != 64 ||
                capture.IsEmpty || capture.Length > 32 * 1024 * 1024) return false;
            // Snapshot the signed bytes so verification and parsing use the same data.
            byte[] signedManifest = manifest.ToArray();
            if (!ReviewedDnsReviewSignature.Matches(signedManifest, signature, _reviewKey))
                return false;
            // Snapshot capture bytes before structural checks and digest comparison.
            byte[] boundCapture = capture.ToArray();
            return ReviewedDnsPacketIntake.Matches(signedManifest,
                Convert.ToHexString(SHA256.HashData(signedManifest)), boundCapture,
                source, sensor, interfaceId, network);
        }
    }
}
