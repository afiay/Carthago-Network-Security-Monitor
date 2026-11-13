using System;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class AssetHistoryCoveragePresentationTests
{
    [Fact]
    public void Mixed_Checkpoints_Separate_Capacity_And_Observed_Rows()
    {
        var now = DateTimeOffset.UtcNow;
        var v2 = Guid.NewGuid();
        var v3 = Guid.NewGuid();
        var row = new ExternalCommunicationRow("12345678-1234-1234-1234-123456789abc",
            "192.168.1.10", "8.8.8.8", 1, now, now,
            Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>());
        var history = new AssetHistorySnapshot(3, Array.Empty<AssetHistoryRow>(), null,
            new[] { new CommunicationHistoryRow(v3, now, row), new CommunicationHistoryRow(v3, now, row) },
            new[] { new CheckpointCoverage(v2, now, null, null), new CheckpointCoverage(v3, now, 2, 0) });
        var summary = AssetHistoryCoveragePresentation.Describe(history);
        Assert.Contains("1 legacy asset-only, 2 communication-capable, 1 with destination rows", summary);
        Assert.Contains("Destination capacity (communication-capable sessions): 0 zero rejections, 1 with rejections, 1 unknown", summary);
        Assert.Contains("Asset capacity (communication-capable sessions): 1 zero rejections, 0 with rejections, 1 unknown", summary);
        Assert.Contains("not eligible comparison sessions", summary);
    }

    [Fact]
    public void Empty_Or_Unreadable_History_Does_Not_Claim_Complete_Capture()
    {
        var summary = AssetHistoryCoveragePresentation.Describe(new(0, Array.Empty<AssetHistoryRow>(), "read error"));
        Assert.Contains("0 legacy asset-only, 0 communication-capable, 0 with destination rows", summary);
        Assert.Contains("Some history could not be read", summary);
        Assert.Contains("do not establish complete capture", summary);
    }
}
