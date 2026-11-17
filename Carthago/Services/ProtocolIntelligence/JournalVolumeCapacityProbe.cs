// SPDX-License-Identifier: MIT
using System;
using System.IO;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Local, OS-reported volume-capacity prerequisite for R531. This is not a
    /// packet-derived health event and must not be converted into an alert without
    /// journal-path ownership, threshold policy and engine integration.
    /// </summary>
    public static class JournalVolumeCapacityProbe
    {
        public static bool TryRead(string journalDirectory, out long availableBytes, out long totalBytes)
        {
            availableBytes = 0;
            totalBytes = 0;
            if (string.IsNullOrWhiteSpace(journalDirectory))
                return false;
            try
            {
                var fullPath = Path.GetFullPath(journalDirectory);
                if (!Directory.Exists(fullPath))
                    return false;
                var root = Path.GetPathRoot(fullPath);
                if (string.IsNullOrEmpty(root))
                    return false;
                var drive = new DriveInfo(root);
                if (!drive.IsReady)
                    return false;
                var free = drive.AvailableFreeSpace;
                var total = drive.TotalSize;
                if (total <= 0 || free < 0 || free > total)
                    return false;
                availableBytes = free;
                totalBytes = total;
                return true;
            }
            catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException)
            {
                return false;
            }
        }

        public static bool IsBelowBothConfiguredLimits(long freeBytes, long totalBytes,
            long minimumFreeBytes, double minimumFreePercent)
        {
            if (totalBytes <= 0 || freeBytes < 0 || freeBytes > totalBytes
                || minimumFreeBytes <= 0 || minimumFreePercent <= 0 || minimumFreePercent > 100
                || double.IsNaN(minimumFreePercent) || double.IsInfinity(minimumFreePercent))
                return false;
            return freeBytes < minimumFreeBytes
                && ((double)freeBytes / totalBytes * 100.0) < minimumFreePercent;
        }
    }
}
