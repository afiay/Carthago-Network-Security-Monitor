using Carthago.Services.Feedback;

namespace Carthago.Tests;

public sealed class DetectionFeedbackStoreTests
{
    [Fact]
    public async Task AppendAsync_NormalizesStoredTimestampToUtc()
    {
        var directory = Path.Combine(Path.GetTempPath(), "carthago-feedback-tests", Guid.NewGuid().ToString("N"));
        var store = new DetectionFeedbackStore(new DetectionFeedbackOptions { DirectoryPath = directory });
        var localOffset = new DateTime(2026, 10, 25, 18, 0, 0, DateTimeKind.Local);
        var item = new DetectionFeedback { EventId = "evt-utc", RuleId = "R42", TimestampUtc = localOffset };

        await store.AppendAsync(item);
        var records = new List<DetectionFeedback>();
        await foreach (var record in store.ReadAllAsync()) records.Add(record);

        Assert.Single(records);
        Assert.Equal(DateTimeKind.Utc, records[0].TimestampUtc.Kind);
        Assert.Equal(localOffset.ToUniversalTime(), records[0].TimestampUtc);
    }

    [Fact]
    public async Task AppendAsync_PersistsAnalystVerdictWithoutModifyingDetection()
    {
        var directory = Path.Combine(Path.GetTempPath(), "carthago-feedback-tests", Guid.NewGuid().ToString("N"));
        var store = new DetectionFeedbackStore(new DetectionFeedbackOptions { DirectoryPath = directory });
        var item = new DetectionFeedback
        {
            EventId = "evt-1",
            RuleId = "R102",
            Verdict = DetectionFeedbackVerdict.FalsePositive,
            Note = "Expected test host",
            TimestampUtc = new DateTime(2026, 4, 29, 12, 0, 0, DateTimeKind.Utc)
        };

        await store.AppendAsync(item);

        var reopened = new DetectionFeedbackStore(new DetectionFeedbackOptions { DirectoryPath = directory });
        var items = new List<DetectionFeedback>();
        await foreach (var feedback in reopened.ReadAllAsync())
            items.Add(feedback);

        var persisted = Assert.Single(items);
        Assert.Equal("evt-1", persisted.EventId);
        Assert.Equal("R102", persisted.RuleId);
        Assert.Equal(DetectionFeedbackVerdict.FalsePositive, persisted.Verdict);
        Assert.Equal("Expected test host", persisted.Note);
    }
}
