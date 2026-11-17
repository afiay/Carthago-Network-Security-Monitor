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
