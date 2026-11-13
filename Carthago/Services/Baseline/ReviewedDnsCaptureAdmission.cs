// SPDX-License-Identifier: MIT
using System;
using System.IO;

namespace Carthago.Services.Baseline
{
    // Offline reservation only, not a baseline observation or readiness counter.
    // The directory must be independently provisioned, private and shared by all
    // admission instances. Never remove a reservation on a failed write.
    internal sealed class ReviewedDnsCaptureAdmission
    {
        private readonly string _directory;
        private readonly ReviewedDnsAuthenticatedIntake _intake;

        internal ReviewedDnsCaptureAdmission(string directory, ReviewedDnsAuthenticatedIntake intake)
        {
            _directory = Path.GetFullPath(directory);
            _intake = intake ?? throw new ArgumentNullException(nameof(intake));
        }

        internal bool TryReserve(ReadOnlySpan<byte> manifest, ReadOnlySpan<byte> signature,
            ReadOnlySpan<byte> capture, string source, string sensor, string interfaceId, string network)
        {
            if (!_intake.TryValidate(manifest, signature, capture, source, sensor, interfaceId,
                network, out var digest)) return false;
            try
            {
                // CreateNew is atomic across competing processes on a local filesystem.
                // Even an empty or partially written marker blocks reuse after failure.
                using var marker = new FileStream(Path.Combine(_directory, digest + ".reserved"),
                    FileMode.CreateNew, FileAccess.Write, FileShare.None);
                marker.WriteByte(1);
                marker.Flush(flushToDisk: true);
                return true;
            }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
        }
    }
}
