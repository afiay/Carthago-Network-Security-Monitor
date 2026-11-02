// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED — 0 EXECUTED.
using Carthago.Services.SessionFiles;
using Xunit;

namespace Carthago.Tests;

public sealed class CarthagoSessionMergeTests
{
    [Fact]
    public void MergePreservesOlderDistinctTrafficWhenCurrentUiWindowHasEvictedIt()
    {
        var older = CarthagoSessionSnapshot.CreateEmpty();
        older.AddRows("Traffic", new[] { new { Id = "1", Source = "192.0.2.1" } });
        var latest = CarthagoSessionSnapshot.CreateEmpty();
        latest.AddRows("Traffic", new[] { new { Id = "2", Source = "192.0.2.2" } });

        var merged = CarthagoSessionSnapshotMerger.Merge(older, latest);

        Assert.Equal(2, merged.Categories["Traffic"].Count);
        Assert.Contains(merged.Categories["Traffic"], row => row.GetProperty("Id").GetString() == "1");
        Assert.Contains(merged.Categories["Traffic"], row => row.GetProperty("Id").GetString() == "2");
    }

    [Fact]
    public void MergeSameUiWindowTwiceDoesNotDuplicateTrafficOrAlerts()
    {
        var capture = CarthagoSessionSnapshot.CreateEmpty();
        capture.AddRows("Traffic", new[] { new { Id = "7", Protocol = "TCP" } });
        capture.AddRows("Alerts", new[] { new { EventId = "alert-7", RuleId = "R102" } });

        var merged = CarthagoSessionSnapshotMerger.Merge(capture,
            CarthagoSessionSnapshotMerger.Merge(capture, capture));

        Assert.Single(merged.Categories["Traffic"]);
        Assert.Single(merged.Categories["Alerts"]);
    }

    [Fact]
    public void MergePrefersTheNewestIncidentRevisionAndKeepsOtherIncidents()
    {
        var older = CarthagoSessionSnapshot.CreateEmpty();
        older.AddRows("Incidents", new[]
        {
            new { Id = "A", Status = "New", UpdatedUtc = "2026-11-01T12:00:00Z" },
            new { Id = "B", Status = "Open", UpdatedUtc = "2026-11-01T12:00:00Z" }
        });
        var latest = CarthagoSessionSnapshot.CreateEmpty();
        latest.AddRows("Incidents", new[]
        {
            new { Id = "A", Status = "Resolved", UpdatedUtc = "2026-11-02T12:00:00Z" }
        });

        var merged = CarthagoSessionSnapshotMerger.Merge(older, latest);

        Assert.Equal(2, merged.Categories["Incidents"].Count);
        Assert.Contains(merged.Categories["Incidents"], row =>
            row.GetProperty("Id").GetString() == "A" && row.GetProperty("Status").GetString() == "Resolved");
    }
}
