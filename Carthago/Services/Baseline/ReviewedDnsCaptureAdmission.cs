// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Carthago.Services.Baseline
{
    // Offline reservation only. All instances must share a private local directory.
    internal sealed class ReviewedDnsCaptureAdmission
    {
        private const long MaxJournalBytes = 64 * 1024 * 1024;
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
                network, out var digest, out var observations) || observations.Length == 0) return false;
            try
            {
                // Legacy digest-only markers cannot establish observation coverage.
                foreach (var legacy in Directory.EnumerateFiles(_directory, "*.reserved"))
                    return false;
                using var journal = new FileStream(Path.Combine(_directory, "admission.v1"),
                    FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                if (journal.Length > MaxJournalBytes) return false;
                var existing = new HashSet<string>(StringComparer.Ordinal);
                var captures = new HashSet<string>(StringComparer.Ordinal);
                // A torn record blocks all further admission rather than allowing replay.
                using (var reader = new StreamReader(journal, Encoding.ASCII, false, 4096, true))
                {
                    if (journal.Length != 0)
                    {
                        journal.Position = journal.Length - 1;
                        if (journal.ReadByte() != 10) return false;
                        journal.Position = 0;
                    }
                    string? line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        var fields = line.Split(',');
                        if (fields.Length < 2 || fields.Length > 20001 ||
                            !IsDigest(fields[0]) || !captures.Add(fields[0])) return false;
                        for (int i = 1; i < fields.Length; i++)
                            if (!IsDigest(fields[i]) || !existing.Add(fields[i])) return false;
                    }
                }
                if (captures.Contains(digest)) return false;
                foreach (var id in observations)
                    if (existing.Contains(id)) return false;
                byte[] record = Encoding.ASCII.GetBytes(digest + "," + string.Join(",", observations) + "\n");
                if (journal.Length + record.Length > MaxJournalBytes) return false;
                journal.Position = journal.Length;
                journal.Write(record);
                journal.Flush(flushToDisk: true);
                return true;
            }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
        }

        private static bool IsDigest(string value)
        {
            if (value.Length != 64) return false;
            foreach (char c in value)
                if (!(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'F')) return false;
            return true;
        }
    }
}
