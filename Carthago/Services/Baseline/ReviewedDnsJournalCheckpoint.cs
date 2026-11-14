// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Carthago.Services.Baseline
{
    // Offline checkpoint verification. Deployment ID, authority key and exact
    // current revision must come from independent trusted configuration/state.
    // A signed older revision is not a substitute for a current revision.
    internal sealed class ReviewedDnsJournalCheckpoint
    {
        private static readonly byte[] Domain = Encoding.ASCII.GetBytes("CARTHAGO-DNS-JOURNAL-V2\0");
        private readonly byte[] _authorityKey;
        private readonly byte[] _deploymentId;
        private readonly ulong _currentRevision;

        internal ReviewedDnsJournalCheckpoint(ReadOnlySpan<byte> authorityKey,
            ReadOnlySpan<byte> deploymentId, ulong currentRevision)
        {
            if (authorityKey.IsEmpty || authorityKey.Length > 512 ||
                deploymentId.Length != 32 || currentRevision == 0)
                throw new ArgumentException("Invalid checkpoint configuration.");
            _authorityKey = authorityKey.ToArray();
            _deploymentId = deploymentId.ToArray();
            _currentRevision = currentRevision;
        }

        // Fixed wire format: domain, 32-byte deployment ID, big-endian uint64
        // revision, 32-byte journal SHA-256. No optional or trailing fields.
        internal bool TryVerify(ReadOnlySpan<byte> checkpoint, ReadOnlySpan<byte> signature,
            out byte[] journalDigest)
        {
            journalDigest = Array.Empty<byte>();
            if (checkpoint.Length != Domain.Length + 72 || signature.Length != 64)
                return false;
            byte[] snapshot = checkpoint.ToArray();
            var bytes = snapshot.AsSpan();
            if (!bytes.Slice(0, Domain.Length).SequenceEqual(Domain) ||
                !bytes.Slice(Domain.Length, 32).SequenceEqual(_deploymentId) ||
                BinaryPrimitives.ReadUInt64BigEndian(bytes.Slice(Domain.Length + 32, 8)) != _currentRevision ||
                !ReviewedDnsReviewSignature.Matches(snapshot, signature, _authorityKey))
                return false;
            journalDigest = bytes.Slice(Domain.Length + 40, 32).ToArray();
            return true;
        }

        internal bool TryReadSummary(ReviewedDnsCaptureAdmission admission, QualifiedDnsScope scope,
            ReadOnlySpan<byte> checkpoint, ReadOnlySpan<byte> signature,
            out int count, out long firstUtcTicks, out long lastUtcTicks)
        {
            count = 0;
            firstUtcTicks = lastUtcTicks = 0;
            return TryVerify(checkpoint, signature, out var digest) &&
                admission.TryReadAnchoredScopeSummary(scope, digest, out count,
                    out firstUtcTicks, out lastUtcTicks);
        }
    }
}
