using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Tuning;
using Carthago.Models;
using Carthago.Services.Feedback;
using Carthago.Services.RuleTuning;

namespace Carthago.Tests;

public sealed class RuleFeedbackAdvisorTests
{
    [Fact]
    public async Task FalsePositive_Feedback_Lowers_Future_Risk_Contribution()
    {
        var store = CreateStore();
        await AppendAsync(store, "R148", DetectionFeedbackVerdict.FalsePositive, 3);
        var advisor = new RuleFeedbackAdvisor(store);
        var summary = await advisor.SummarizeAsync("R148");
        var recommendation = advisor.Recommend(Decision("R148"), summary);

        Assert.True(recommendation.RiskContributionMultiplier < 1.0);
    }

    [Fact]
    public async Task Repeated_FalsePositives_Suggest_Shadow_Or_Allowlist()
    {
        var store = CreateStore();
        await AppendAsync(store, "R113", DetectionFeedbackVerdict.FalsePositive, 3);
        await AppendAsync(store, "R113", DetectionFeedbackVerdict.ExpectedActivity, 1);
        var advisor = new RuleFeedbackAdvisor(store);
        var recommendation = advisor.Recommend(Decision("R113"), await advisor.SummarizeAsync("R113"));

        Assert.Equal(RuleMode.Shadow, recommendation.RecommendedMode);
        Assert.Contains("Approved.MqttBrokers", recommendation.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Repeated_TruePositives_Suggest_Keeping_Alert()
    {
        var store = CreateStore();
        await AppendAsync(store, "R102", DetectionFeedbackVerdict.TruePositive, 3);
        var advisor = new RuleFeedbackAdvisor(store);
        var recommendation = advisor.Recommend(Decision("R102"), await advisor.SummarizeAsync("R102"));

        Assert.Equal(RuleMode.Alert, recommendation.RecommendedMode);
        Assert.Contains("keep Alert", recommendation.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Feedback_Recommendations_Do_Not_Mutate_Original_DetectionEvent()
    {
        var store = CreateStore();
        await AppendAsync(store, "R148", DetectionFeedbackVerdict.FalsePositive, 3);
        var advisor = new RuleFeedbackAdvisor(store);
        var evt = new DetectionEvent
        {
            RuleId = "R148",
            Description = "TLS to dynamic DNS host",
            ConfidenceScore = 0.74,
            Severity = SeverityLevel.Medium,
            SourceIp = "10.0.0.10",
            DestinationIp = "203.0.113.50"
        };

        _ = advisor.Recommend(Decision("R148"), await advisor.SummarizeAsync("R148"));

        Assert.Equal("R148", evt.RuleId);
        Assert.Equal("TLS to dynamic DNS host", evt.Description);
        Assert.Equal(0.74, evt.ConfidenceScore, 3);
        Assert.Equal(SeverityLevel.Medium, evt.Severity);
    }

    [Fact]
    public async Task Feedback_Never_Disables_Rule_Automatically_Without_Explicit_Config()
    {
        var store = CreateStore();
        await AppendAsync(store, "R148", DetectionFeedbackVerdict.FalsePositive, 4);
        var advisor = new RuleFeedbackAdvisor(store);
        var recommendation = advisor.Recommend(Decision("R148"), await advisor.SummarizeAsync("R148"));

        Assert.NotEqual(RuleMode.Disabled, recommendation.RecommendedMode);
    }

    private static DetectionFeedbackStore CreateStore()
        => new(new DetectionFeedbackOptions { DirectoryPath = Path.Combine(Path.GetTempPath(), "carthago-feedback-tests", Guid.NewGuid().ToString("N")) });

    private static async Task AppendAsync(DetectionFeedbackStore store, string ruleId, DetectionFeedbackVerdict verdict, int count)
    {
        for (var i = 0; i < count; i++)
        {
            await store.AppendAsync(new DetectionFeedback
            {
                RuleId = ruleId,
                EventId = $"evt-{ruleId}-{i}",
                Verdict = verdict,
                TimestampUtc = new DateTime(2026, 4, 28, 12, i, 0, DateTimeKind.Utc)
            });
        }
    }

    private static RuleTuningDecision Decision(string ruleId)
    {
        var descriptor = RuleCatalog.Find(ruleId) ?? throw new InvalidOperationException($"Missing descriptor for {ruleId}.");
        var evt = new DetectionEvent { RuleId = ruleId, ConfidenceScore = 0.95, Severity = SeverityLevel.High, Description = descriptor.Name, TimestampUtc = DateTime.UtcNow };
        var record = new TrafficRecord { Source = "10.0.0.10", Destination = "203.0.113.20", Protocol = "HTTP", DestinationPort = 443, HttpHost = "example.test", HttpUri = "/" };
        return RuleTuningCatalog.Resolve("SmallBusiness", descriptor, evt, record);
    }
}
