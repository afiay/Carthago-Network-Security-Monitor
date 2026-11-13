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
        private const int MaxRecordBytes = 65 * 20001;
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
                // Parse exact ASCII LF records with a bounded buffer. StreamReader
                // would accept CR/BOM variants and allocate an unbounded line.
                using (var reader = new BufferedStream(journal, 4096))
                {
                    if (!ReadJournal(reader, captures, existing)) return false;
                    if (captures.Contains(digest)) return false;
                    foreach (var id in observations)
                        if (existing.Contains(id)) return false;
                    byte[] record = Encoding.ASCII.GetBytes(digest + "," + string.Join(",", observations) + "\n");
                    if (journal.Length + record.Length > MaxJournalBytes) return false;
                    reader.Write(record);
                    reader.Flush();
                    journal.Flush(flushToDisk: true);
                    return true;
                }
            }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
        }

        private static bool ReadJournal(Stream reader, HashSet<string> captures, HashSet<string> existing)
        {
            var field = new byte[64];
            int length = 0, fields = 0, recordBytes = 0;
            string? previousObservation = null;
            int value;
            while ((value = reader.ReadByte()) != -1)
            {
                if (++recordBytes > MaxRecordBytes) return false;
                if (value == ',' || value == 10)
                {
                    if (length != 64 || ++fields > 20001) return false;
                    string digest = Encoding.ASCII.GetString(field);
                    if (fields == 1)
                    {
                        if (!captures.Add(digest)) return false;
                    }
                    else
                    {
                        // Intake emits sorted unique identities; reject noncanonical records.
                        if (previousObservation != null &&
                            string.CompareOrdinal(previousObservation, digest) >= 0) return false;
                        if (!existing.Add(digest)) return false;
                        previousObservation = digest;
                    }
                    length = 0;
                    if (value == 10)
                    {
                        if (fields < 2) return false;
                        fields = 0;
                        previousObservation = null;
                        recordBytes = 0;
                    }
                }
                else
                {
                    if (length == 64 || !((value >= '0' && value <= '9') ||
                        (value >= 'A' && value <= 'F'))) return false;
                    field[length++] = (byte)value;
                }
            }
            return recordBytes == 0;
        }

    }
}
