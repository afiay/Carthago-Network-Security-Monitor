// SPDX-License-Identifier: MIT
using System;
using System.IO;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests
{
    public sealed class DetectionJournalCapacityOwnershipTests
    {
        [Fact]
        public void ConfiguredDirectoryIsUsedRatherThanDefaultJournalPath()
        {
            var missing = Path.Combine(Path.GetTempPath(), "carthago-missing-journal-" + Guid.NewGuid().ToString("N"));
            var journal = new DetectionJournal(new DetectionJournalOptions
            {
                DirectoryPath = missing,
                CreateDirectoryIfMissing = false
            });

            Assert.False(journal.TryReadConfiguredVolumeCapacity(out var free, out var total));
            Assert.Equal(0, free);
            Assert.Equal(0, total);
            Assert.False(Directory.Exists(missing));
        }

        [Fact]
        public void InvalidThresholdPolicyCannotProduceLowSpaceFinding()
        {
            var journal = new DetectionJournal(new DetectionJournalOptions
            {
                DirectoryPath = Path.GetTempPath()
            });
            Assert.False(journal.TryEvaluateConfiguredVolumeCapacity(
                1024, double.NaN, out var low, out var free, out var total));
            Assert.False(low);
            Assert.Equal(0, free);
            Assert.Equal(0, total);
        }

        [Fact]
        public void MissingConfiguredDirectoryIsUnknownNotLowSpace()
        {
            var missing = Path.Combine(Path.GetTempPath(), "carthago-absent-" + Guid.NewGuid().ToString("N"));
            var journal = new DetectionJournal(new DetectionJournalOptions
            {
                DirectoryPath = missing,
                CreateDirectoryIfMissing = false
            });
            Assert.False(journal.TryEvaluateConfiguredVolumeCapacity(
                long.MaxValue, 100, out var low, out var free, out var total));
            Assert.False(low);
            Assert.Equal(0, free);
            Assert.Equal(0, total);
            Assert.False(Directory.Exists(missing));
        }

        [Fact]
        public void ExistingDirectoryEvaluatesThresholdsWithoutWriting()
        {
            var directory = Path.Combine(Path.GetTempPath(), "carthago-capacity-policy-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            try
            {
                var journal = new DetectionJournal(new DetectionJournalOptions { DirectoryPath = directory });
                if (journal.TryReadConfiguredVolumeCapacity(out var free, out var total) && free > 0)
                {
                    Assert.True(journal.TryEvaluateConfiguredVolumeCapacity(
                        long.MaxValue, 100, out var low, out var observedFree, out var observedTotal));
                    Assert.True(observedTotal > 0);
                    Assert.InRange(observedFree, 0, observedTotal);
                    Assert.Equal(
                        observedFree < long.MaxValue && (double)observedFree / observedTotal * 100 < 100,
                        low);
                }
                Assert.Empty(Directory.GetFiles(directory));
            }
            finally
            {
                Directory.Delete(directory);
            }
        }

        [Fact]
        public void ExistingOwnedDirectoryCanBeSampledWithoutCreatingJournalFiles()
        {
            var directory = Path.Combine(Path.GetTempPath(), "carthago-capacity-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            try
            {
                var journal = new DetectionJournal(new DetectionJournalOptions { DirectoryPath = directory });
                var result = journal.TryReadConfiguredVolumeCapacity(out var free, out var total);
                if (result)
                {
                    Assert.True(total > 0);
                    Assert.InRange(free, 0, total);
                }
                Assert.Empty(Directory.GetFiles(directory));
            }
            finally
            {
                Directory.Delete(directory);
            }
        }
    }
}
