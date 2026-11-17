// SPDX-License-Identifier: MIT
using System;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests.ProtocolIntelligence
{
    public sealed class JournalVolumeCapacityProbeTests
    {
        [Fact]
        public void ReadsExistingLocalDirectoryWithoutPacketInput()
        {
            Assert.True(JournalVolumeCapacityProbe.TryRead(AppContext.BaseDirectory, out var free, out var total));
            Assert.InRange(free, 0, total);
            Assert.True(total > 0);
        }

        [Fact]
        public void MissingJournalDirectoryFailsClosed()
        {
            Assert.False(JournalVolumeCapacityProbe.TryRead(string.Empty, out _, out _));
            Assert.False(JournalVolumeCapacityProbe.TryRead(
                System.IO.Path.Combine(System.IO.Path.GetTempPath(), Guid.NewGuid().ToString("N")), out _, out _));
        }

        [Fact]
        public void RedirectedJournalDirectoryCannotSupplyVolumeCapacity()
        {
            var root = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "carthago-journal-probe-" + Guid.NewGuid().ToString("N"));
            var actual = System.IO.Path.Combine(root, "actual");
            var redirected = System.IO.Path.Combine(root, "redirected");
            System.IO.Directory.CreateDirectory(actual);
            try
            {
                try
                {
                    System.IO.Directory.CreateSymbolicLink(redirected, actual);
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or System.IO.IOException or PlatformNotSupportedException)
                {
                    // Symlink creation is not available on all Windows test hosts.
                    return;
                }
                Assert.False(JournalVolumeCapacityProbe.TryRead(redirected, out _, out _));
            }
            finally
            {
                if (System.IO.Directory.Exists(redirected))
                    System.IO.Directory.Delete(redirected);
                System.IO.Directory.Delete(root, recursive: true);
            }
        }

        [Theory]
        [InlineData(4, 100, 10, 5, true)]
        [InlineData(6, 100, 10, 5, false)]
        [InlineData(4, 100, 3, 5, false)]
        [InlineData(4, 100, 10, 0, false)]
        [InlineData(-1, 100, 10, 5, false)]
        public void RequiresBothValidConfiguredThresholds(long free, long total, long bytes, double percent, bool expected)
        {
            Assert.Equal(expected, JournalVolumeCapacityProbe.IsBelowBothConfiguredLimits(free, total, bytes, percent));
        }
    }
}
