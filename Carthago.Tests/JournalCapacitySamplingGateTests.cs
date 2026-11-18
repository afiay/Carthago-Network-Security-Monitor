// SPDX-License-Identifier: MIT
using System;
using System.IO;
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
    }
}
