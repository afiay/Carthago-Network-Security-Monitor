using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class RulePersistenceMetricsTests
{
    [Fact]
    public async Task AppendAsync_And_EngineMetric_Increment_Counts_Persisted_Event_Once()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"carthago-journal-{Guid.NewGuid():N}");
        var journal = new DetectionJournal(new DetectionJournalOptions
        {
            DirectoryPath = directory
        });

        var evt = new DetectionEvent
        {
            RuleId = "R102",
            RuleName = "Synthetic DNS tunnel",
            Description = "Synthetic persisted detection",
            TimestampUtc = new DateTime(2026, 4, 28, 10, 0, 0, DateTimeKind.Utc),
            SourceIp = "10.0.0.10",
            DestinationIp = "203.0.113.20",
            DestinationPort = 53,
            Protocol = "DNS",
            Severity = SeverityLevel.High
        };

        RuleEngineMetrics.Reset("R102");

        var writeResult = await journal.AppendAsync(evt);

        Assert.True(writeResult.Succeeded);
        Assert.Equal(0, RuleEngineMetrics.Get("R102", RuleMetricNames.RulePersistedTotal));

        RuleEngineMetrics.Increment("R102", RuleMetricNames.RulePersistedTotal);

        Assert.Equal(1, RuleEngineMetrics.Get("R102", RuleMetricNames.RulePersistedTotal));
        Assert.Equal(0, RuleEngineMetrics.Get("R102", RuleMetricNames.JournalWriteFailedTotal));
        Assert.True(File.Exists(writeResult.JournalPath));
    }
}
