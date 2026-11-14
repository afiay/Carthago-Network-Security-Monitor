// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Globalization;
using System.Security.Cryptography;

namespace Carthago.Services.Baseline
{
    // Offline reservation only. All instances must share a private local directory.
    internal sealed class ReviewedDnsCaptureAdmission
    {
        private const long MaxJournalBytes = 64 * 1024 * 1024;
        private const int MaxRecordBytes = 65 * 2 + 82 * 20000;
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
                network, out var digest, out var observations, out var ticks) || observations.Length == 0 ||
                observations.Length != ticks.Length || observations.Length > 20000) return false;
            try
            {
                // Legacy digest-only markers cannot establish observation coverage.
                foreach (var legacy in Directory.EnumerateFiles(_directory, "*.reserved"))
                    return false;
                if (File.Exists(Path.Combine(_directory, "admission.v1"))) return false;
                using var journal = new FileStream(Path.Combine(_directory, "admission.v2"),
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
                    string scopeDigest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
                        QualifiedDnsScope.Create(source, sensor, interfaceId, network).Subject)));
                    var recordText = new StringBuilder(digest).Append(',').Append(scopeDigest);
                    for (int i = 0; i < observations.Length; i++)
                        recordText.Append(',').Append(observations[i]).Append(':')
                            .Append(ticks[i].ToString("X16", CultureInfo.InvariantCulture));
                    byte[] record = Encoding.ASCII.GetBytes(recordText.Append('\n').ToString());
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

        // Diagnostic only: syntactic journal validity is not trusted provenance.
        // Publish no partial result on corruption or concurrent writer contention.
        internal bool TryReadScopeSummary(QualifiedDnsScope scope, out int count,
            out long firstUtcTicks, out long lastUtcTicks)
            => TryReadSummary(scope, null, out count, out firstUtcTicks, out lastUtcTicks);

        // Expected digest must come from an independently controlled current checkpoint.
        // This verifies exact bytes, not the authority or freshness of that checkpoint.
        internal bool TryReadAnchoredScopeSummary(QualifiedDnsScope scope,
            ReadOnlySpan<byte> expectedDigest, out int count, out long firstUtcTicks, out long lastUtcTicks)
        {
            count = 0;
            firstUtcTicks = lastUtcTicks = 0;
            if (expectedDigest.Length != 32) return false;
            return TryReadSummary(scope, expectedDigest.ToArray(), out count, out firstUtcTicks, out lastUtcTicks);
        }

        private bool TryReadSummary(QualifiedDnsScope scope, byte[]? expectedDigest, out int count,
            out long firstUtcTicks, out long lastUtcTicks)
        {
            count = 0;
            firstUtcTicks = lastUtcTicks = 0;
            string wanted = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(scope.Subject)));
            int found = 0;
            long first = long.MaxValue, last = 0;
            try
            {
                foreach (var legacy in Directory.EnumerateFiles(_directory, "*.reserved"))
                    return false;
                if (File.Exists(Path.Combine(_directory, "admission.v1"))) return false;
                using var journal = new FileStream(Path.Combine(_directory, "admission.v2"),
                    FileMode.Open, FileAccess.Read, FileShare.None);
                if (journal.Length > MaxJournalBytes) return false;
                if (expectedDigest != null)
                {
                    // Parse the same exclusively opened file that was hashed.
                    if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(journal), expectedDigest))
                        return false;
                    journal.Position = 0;
                }
                using var reader = new BufferedStream(journal, 4096);
                if (!ReadJournal(reader, new HashSet<string>(StringComparer.Ordinal),
                    new HashSet<string>(StringComparer.Ordinal), (scopeDigest, ticks) =>
                    {
                        if (!string.Equals(scopeDigest, wanted, StringComparison.Ordinal)) return;
                        found++;
                        first = Math.Min(first, ticks);
                        last = Math.Max(last, ticks);
                    })) return false;
                count = found;
                firstUtcTicks = found == 0 ? 0 : first;
                lastUtcTicks = last;
                return true;
            }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
        }

        private static bool ReadJournal(Stream reader, HashSet<string> captures, HashSet<string> existing,
            Action<string, long>? observe = null)
        {
            var field = new byte[81];
            int length = 0, fields = 0, recordBytes = 0;
            string? previousObservation = null;
            string scopeDigest = string.Empty;
            int value;
            while ((value = reader.ReadByte()) != -1)
            {
                if (++recordBytes > MaxRecordBytes) return false;
                if (value == ',' || value == 10)
                {
                    if (++fields > 20002 || length != (fields <= 2 ? 64 : 81)) return false;
                    string digest = Encoding.ASCII.GetString(field, 0, 64);
                    if (fields == 1)
                    {
                        if (!captures.Add(digest)) return false;
                    }
                    else if (fields == 2) scopeDigest = digest;
                    else if (fields > 2)
                    {
                        if (field[64] != ':' ||
                            !long.TryParse(Encoding.ASCII.GetString(field, 65, 16),
                                NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out long ticks) ||
                            ticks < DateTime.UnixEpoch.Ticks || ticks > DateTime.MaxValue.Ticks)
                            return false;
                        // Intake emits sorted unique identities; reject noncanonical records.
                        if (previousObservation != null &&
                            string.CompareOrdinal(previousObservation, digest) >= 0) return false;
                        if (!existing.Add(digest)) return false;
                        previousObservation = digest;
                        observe?.Invoke(scopeDigest, ticks);
                    }
                    length = 0;
                    if (value == 10)
                    {
                        if (fields < 3) return false;
                        fields = 0;
                        previousObservation = null;
                        recordBytes = 0;
                    }
                }
                else
                {
                    int limit = fields < 2 ? 64 : 81;
                    if (length == limit) return false;
                    if (fields >= 2 && length == 64)
                    {
                        if (value != ':') return false;
                    }
                    else if (!((value >= '0' && value <= '9') ||
                        (value >= 'A' && value <= 'F'))) return false;
                    field[length++] = (byte)value;
                }
            }
            return recordBytes == 0;
        }

    }
}
