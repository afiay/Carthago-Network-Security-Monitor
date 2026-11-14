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
        private readonly QualifiedDnsScope _authorizedScope;

        internal ReviewedDnsAuthenticatedIntake(ReadOnlySpan<byte> provisionedReviewKey,
            QualifiedDnsScope authorizedScope)
        {
            if (provisionedReviewKey.IsEmpty || provisionedReviewKey.Length > 512)
                throw new ArgumentException("Invalid review key size.", nameof(provisionedReviewKey));
            _authorizedScope = authorizedScope ?? throw new ArgumentNullException(nameof(authorizedScope));
            _reviewKey = provisionedReviewKey.ToArray();
        }

        internal bool Matches(ReadOnlySpan<byte> manifest, ReadOnlySpan<byte> signature,
            ReadOnlySpan<byte> capture, string source, string sensor, string interfaceId, string network)
            => TryValidate(manifest, signature, capture, source, sensor, interfaceId, network, out _);

        internal bool TryValidate(ReadOnlySpan<byte> manifest, ReadOnlySpan<byte> signature,
            ReadOnlySpan<byte> capture, string source, string sensor, string interfaceId, string network,
            out string captureDigest)
            => TryValidate(manifest, signature, capture, source, sensor, interfaceId, network,
                out captureDigest, out _);

        internal bool TryValidate(ReadOnlySpan<byte> manifest, ReadOnlySpan<byte> signature,
            ReadOnlySpan<byte> capture, string source, string sensor, string interfaceId, string network,
            out string captureDigest, out string[] observations)
        {
            return TryValidate(manifest, signature, capture, source, sensor, interfaceId, network,
                out captureDigest, out observations, out _);
        }

        internal bool TryValidate(ReadOnlySpan<byte> manifest, ReadOnlySpan<byte> signature,
            ReadOnlySpan<byte> capture, string source, string sensor, string interfaceId, string network,
            out string captureDigest, out string[] observations, out long[] utcTicks)
        {
            utcTicks = Array.Empty<long>();
            observations = Array.Empty<string>();
            captureDigest = string.Empty;
            if (manifest.IsEmpty || manifest.Length > 16384 || signature.Length != 64 ||
                capture.IsEmpty || capture.Length > 32 * 1024 * 1024) return false;
            QualifiedDnsScope submittedScope;
            try { submittedScope = QualifiedDnsScope.Create(source, sensor, interfaceId, network); }
            catch (ArgumentException) { return false; }
            if (!string.Equals(_authorizedScope.Subject, submittedScope.Subject, StringComparison.Ordinal))
                return false;
            // Snapshot the signed bytes so verification and parsing use the same data.
            byte[] signedManifest = manifest.ToArray();
            if (!ReviewedDnsReviewSignature.Matches(signedManifest, signature, _reviewKey))
                return false;
            // Snapshot capture bytes before structural checks and digest comparison.
            byte[] boundCapture = capture.ToArray();
            if (!ReviewedDnsPacketIntake.TryGetObservations(signedManifest,
                Convert.ToHexString(SHA256.HashData(signedManifest)), boundCapture,
                source, sensor, interfaceId, network, out observations, out utcTicks)) return false;
            captureDigest = Convert.ToHexString(SHA256.HashData(boundCapture));
            return true;
        }
    }
}
