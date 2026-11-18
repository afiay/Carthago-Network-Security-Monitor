// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Threading.Tasks;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests
{
    public sealed class JournalCapacitySamplingGateTests
    {
        [Fact]
        public void TwoSeparatedOwnedSamplesRequiredForLowSpaceConfirmation()
        {
            var directory = Path.Combine(Path.GetTempPath(), "carthago-gate-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            try
            {
                var journal = new DetectionJournal(new DetectionJournalOptions { DirectoryPath = directory });
                var gate = new JournalCapacitySamplingGate(journal, long.MaxValue, 100, TimeSpan.FromMinutes(1));
                var now = new DateTime(2026, 11, 18, 0, 0, 0, DateTimeKind.Utc);
                if (!journal.TryReadConfiguredVolumeCapacity(out var free, out var total) || free <= 0 || free >= total)
                    return; // Host has no representative positive capacity reading.
                Assert.True(gate.TrySample(now, false, out var first, out _, out _));
                Assert.False(first);
                Assert.False(gate.TrySample(now.AddSeconds(30), false, out var early, out _, out _));
                Assert.False(early);
                Assert.True(gate.TrySample(now.AddMinutes(1), false, out var confirmed, out _, out _));
                Assert.True(confirmed);
                Assert.Empty(Directory.GetFiles(directory));
            }
            finally { Directory.Delete(directory); }
        }

        [Fact]
        public void MaintenanceAndInvalidClockResetPendingConfirmation()
        {
            var missing = Path.Combine(Path.GetTempPath(), "carthago-gate-missing-" + Guid.NewGuid().ToString("N"));
            var journal = new DetectionJournal(new DetectionJournalOptions
            {
                DirectoryPath = missing, CreateDirectoryIfMissing = false
            });
            var gate = new JournalCapacitySamplingGate(journal, 1024, 10, TimeSpan.FromMinutes(1));
            var now = new DateTime(2026, 11, 18, 0, 0, 0, DateTimeKind.Utc);
            Assert.False(gate.TrySample(now, true, out var low, out _, out _));
            Assert.False(low);
            Assert.False(gate.TrySample(DateTime.SpecifyKind(now, DateTimeKind.Unspecified), false, out low, out _, out _));
            Assert.False(low);
            Assert.False(gate.TrySample(now, false, out low, out _, out _));
            Assert.False(low);
            Assert.False(Directory.Exists(missing));
        }

        [Fact]
        public void StaleFirstSampleRequiresTwoNewFreshSamples()
        {
            var directory = Path.Combine(Path.GetTempPath(), "carthago-gate-gap-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            try
            {
                var journal = new DetectionJournal(new DetectionJournalOptions { DirectoryPath = directory });
                if (!journal.TryReadConfiguredVolumeCapacity(out var free, out var total) || free <= 0 || free >= total)
                    return;
                var gate = new JournalCapacitySamplingGate(journal, long.MaxValue, 100,
                    TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(2));
                var start = new DateTime(2026, 11, 18, 0, 0, 0, DateTimeKind.Utc);
                Assert.True(gate.TrySample(start, false, out var low, out _, out _));
                Assert.False(low);
                Assert.True(gate.TrySample(start.AddMinutes(10), false, out low, out _, out _));
                Assert.False(low);
                Assert.True(gate.TrySample(start.AddMinutes(11), false, out low, out _, out _));
                Assert.True(low);
            }
            finally { Directory.Delete(directory); }
        }

        [Fact]
        public void MaximumSamplingIntervalMustNotPrecedeMinimum()
        {
            var journal = new DetectionJournal(new DetectionJournalOptions());
            Assert.Throws<ArgumentOutOfRangeException>(() => new JournalCapacitySamplingGate(
                journal, 1024, 10, TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(1)));
        }
        [Fact]
        public void SustainedLowSpaceConfirmsOnceUntilGateIsReset()
        {
            var directory = Path.Combine(Path.GetTempPath(), "carthago-gate-episode-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            try
            {
                var journal = new DetectionJournal(new DetectionJournalOptions { DirectoryPath = directory });
                if (!journal.TryReadConfiguredVolumeCapacity(out var free, out var total) || free <= 0 || free >= total)
                    return;
                var gate = new JournalCapacitySamplingGate(journal, long.MaxValue, 100, TimeSpan.FromMinutes(1));
                var at = new DateTime(2026, 11, 18, 0, 0, 0, DateTimeKind.Utc);
                Assert.True(gate.TrySample(at, false, out var first, out _, out _));
                Assert.False(first);
                Assert.True(gate.TrySample(at.AddMinutes(1), false, out var confirmed, out _, out _));
                Assert.True(confirmed);
                Assert.True(gate.TrySample(at.AddMinutes(2), false, out var repeated, out _, out _));
                Assert.False(repeated);
                gate.Reset();
                Assert.True(gate.TrySample(at.AddMinutes(3), false, out var rearmedFirst, out _, out _));
                Assert.False(rearmedFirst);
                Assert.True(gate.TrySample(at.AddMinutes(4), false, out var rearmedConfirmation, out _, out _));
                Assert.True(rearmedConfirmation);
            }
            finally { Directory.Delete(directory); }
        }

        [Fact]
        public void DuplicateTickDoesNotRearmConfirmedLowSpaceEpisode()
        {
            var directory = Path.Combine(Path.GetTempPath(), "carthago-gate-duplicate-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            try
            {
                var journal = new DetectionJournal(new DetectionJournalOptions { DirectoryPath = directory });
                if (!journal.TryReadConfiguredVolumeCapacity(out var free, out var total) || free <= 0 || free >= total)
                    return;
                var gate = new JournalCapacitySamplingGate(journal, long.MaxValue, 100, TimeSpan.FromMinutes(1));
                var at = new DateTime(2026, 11, 18, 0, 0, 0, DateTimeKind.Utc);
                Assert.True(gate.TrySample(at, false, out var first, out _, out _));
                Assert.False(first);
                Assert.True(gate.TrySample(at.AddMinutes(1), false, out var confirmed, out _, out _));
                Assert.True(confirmed);
                Assert.False(gate.TrySample(at.AddMinutes(1), false, out var duplicate, out _, out _));
                Assert.False(duplicate);
                Assert.True(gate.TrySample(at.AddMinutes(2), false, out var subsequent, out _, out _));
                Assert.False(subsequent);
            }
            finally { Directory.Delete(directory); }
        }

        [Fact]
        public void ConcurrentIdenticalSamplesCannotConfirmLowSpace()
        {
            var directory = Path.Combine(Path.GetTempPath(), "carthago-gate-race-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            try
            {
                var journal = new DetectionJournal(new DetectionJournalOptions { DirectoryPath = directory });
                if (!journal.TryReadConfiguredVolumeCapacity(out var free, out var total) || free <= 0 || free >= total)
                    return;
                var gate = new JournalCapacitySamplingGate(journal, long.MaxValue, 100,
                    TimeSpan.FromMinutes(1));
                var at = new DateTime(2026, 11, 18, 0, 0, 0, DateTimeKind.Utc);
                var confirmations = 0;
                Parallel.For(0, 16, index =>
                {
                    if (gate.TrySample(at, false, out var confirmed, out _, out _) && confirmed)
                        System.Threading.Interlocked.Increment(ref confirmations);
                });
                Assert.Equal(0, confirmations);
                Assert.True(gate.TrySample(at.AddMinutes(1), false, out var second, out _, out _));
                Assert.True(second);
            }
            finally { Directory.Delete(directory); }
        }

        [Fact]
        public void DeterministicCapacitySourceConfirmsOnceAndRearmsAfterRecovery()
        {
            var journal = new DetectionJournal(new DetectionJournalOptions());
            var low = true;
            var gate = new JournalCapacitySamplingGate(journal, 1000, 10,
                TimeSpan.FromMinutes(1), capacityReader: (bytes, percent) =>
                    (true, low, low ? 50L : 5000L, 10000L));
            var at = new DateTime(2026, 11, 18, 0, 0, 0, DateTimeKind.Utc);
            Assert.True(gate.TrySample(at, false, out var first, out _, out _));
            Assert.False(first);
            Assert.True(gate.TrySample(at.AddMinutes(1), false, out var confirmed, out _, out _));
            Assert.True(confirmed);
            Assert.True(gate.TrySample(at.AddMinutes(2), false, out var repeated, out _, out _));
            Assert.False(repeated);
            low = false;
            Assert.True(gate.TrySample(at.AddMinutes(3), false, out var recovered, out _, out _));
            Assert.False(recovered);
            low = true;
            Assert.True(gate.TrySample(at.AddMinutes(4), false, out var rearmFirst, out _, out _));
            Assert.False(rearmFirst);
            Assert.True(gate.TrySample(at.AddMinutes(5), false, out var rearmConfirmed, out _, out _));
            Assert.True(rearmConfirmed);
        }

        [Fact]
        public void InvalidInjectedCapacityResetsPendingConfirmation()
        {
            var journal = new DetectionJournal(new DetectionJournalOptions());
            var invalid = false;
            var gate = new JournalCapacitySamplingGate(journal, 1000, 10,
                TimeSpan.FromMinutes(1), capacityReader: (bytes, percent) =>
                    (true, true, invalid ? 11000L : 50L, 10000L));
            var at = new DateTime(2026, 11, 18, 0, 0, 0, DateTimeKind.Utc);
            Assert.True(gate.TrySample(at, false, out var first, out _, out _));
            Assert.False(first);
            invalid = true;
            Assert.False(gate.TrySample(at.AddMinutes(1), false, out var rejected, out _, out _));
            Assert.False(rejected);
            invalid = false;
            Assert.True(gate.TrySample(at.AddMinutes(2), false, out var freshFirst, out _, out _));
            Assert.False(freshFirst);
            Assert.True(gate.TrySample(at.AddMinutes(3), false, out var confirmed, out _, out _));
            Assert.True(confirmed);
        }

    }
}
