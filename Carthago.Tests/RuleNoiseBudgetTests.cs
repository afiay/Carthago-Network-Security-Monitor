using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Tuning;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.RuleTuning;

namespace Carthago.Tests;

public sealed class RuleNoiseBudgetTests
{
    [Fact]
    public async Task NoiseBudget_Demotes_To_Shadow_Then_Suppressed_While_Keeping_Journal_Durable()
    {
        var store = new RuleNoiseBudgetStore(new Dictionary<string, RuleNoiseBudget>
        {
            ["R084"] = new(MaxAlertsPerRulePerHour: 1, MaxAlertsPerHostPerRulePerHour: 1, MaxShadowEventsPerRulePerHour: 1)
        });
        var evaluator = new RuleNoiseBudgetEvaluator(store);
        var descriptor = Descriptor("R084");
        var tuning = RuleTuningCatalog.Resolve("SmallBusiness", descriptor, CreateEvent("R084", SeverityLevel.High), CreateRecord());
        var first = evaluator.Evaluate(CreateEvent("R084", SeverityLevel.High), descriptor, tuning, new DateTime(2026, 4, 28, 12, 0, 0, DateTimeKind.Utc));
        var secondEvent = CreateEvent("R084", SeverityLevel.High);
        var second = evaluator.Evaluate(secondEvent, descriptor, tuning, new DateTime(2026, 4, 28, 12, 5, 0, DateTimeKind.Utc));
        var thirdEvent = CreateEvent("R084", SeverityLevel.High);
        var third = evaluator.Evaluate(thirdEvent, descriptor, tuning, new DateTime(2026, 4, 28, 12, 10, 0, DateTimeKind.Utc));

        Assert.Equal(RuleNoiseBudgetDisposition.Allowed, first.Disposition);
        Assert.Equal(RuleNoiseBudgetDisposition.Shadowed, second.Disposition);
        Assert.Equal(RuleNoiseBudgetDisposition.Suppressed, third.Disposition);

        thirdEvent.SuppressionStatus = third.Disposition == RuleNoiseBudgetDisposition.Suppressed ? DetectionSuppressionStatus.Suppressed : DetectionSuppressionStatus.None;
        var directory = Path.Combine(Path.GetTempPath(), $"carthago-noise-budget-{Guid.NewGuid():N}");
        var journal = new DetectionJournal(new DetectionJournalOptions { DirectoryPath = directory });
        var writeResult = await journal.AppendAsync(thirdEvent);

        Assert.True(writeResult.Succeeded);
        Assert.True(File.Exists(writeResult.JournalPath));
        Assert.Contains("hourly budget", third.Recommendation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void NoiseBudget_Reports_Diagnostics_Reason()
    {
        var store = new RuleNoiseBudgetStore(new Dictionary<string, RuleNoiseBudget>
        {
            ["R084"] = new(MaxAlertsPerRulePerHour: 1, MaxAlertsPerHostPerRulePerHour: 1, MaxShadowEventsPerRulePerHour: 1)
        });
        var evaluator = new RuleNoiseBudgetEvaluator(store);
        var descriptor = Descriptor("R084");
        var tuning = RuleTuningCatalog.Resolve("SmallBusiness", descriptor, CreateEvent("R084", SeverityLevel.High), CreateRecord());

        evaluator.Evaluate(CreateEvent("R084", SeverityLevel.High), descriptor, tuning, new DateTime(2026, 4, 28, 12, 0, 0, DateTimeKind.Utc));
        evaluator.Evaluate(CreateEvent("R084", SeverityLevel.High), descriptor, tuning, new DateTime(2026, 4, 28, 12, 1, 0, DateTimeKind.Utc));

        var snapshot = evaluator.Snapshot("R084", "10.0.0.10", new DateTime(2026, 4, 28, 12, 2, 0, DateTimeKind.Utc));

        Assert.NotNull(snapshot.LastDecision);
        Assert.Contains("Noise budget exceeded", snapshot.LastDecision!.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void NoiseBudget_Resets_After_The_Time_Window()
    {
        var store = new RuleNoiseBudgetStore(new Dictionary<string, RuleNoiseBudget>
        {
            ["R084"] = new(MaxAlertsPerRulePerHour: 1, MaxAlertsPerHostPerRulePerHour: 1, MaxShadowEventsPerRulePerHour: 1)
        });
        var evaluator = new RuleNoiseBudgetEvaluator(store);
        var descriptor = Descriptor("R084");
        var tuning = RuleTuningCatalog.Resolve("SmallBusiness", descriptor, CreateEvent("R084", SeverityLevel.High), CreateRecord());

        evaluator.Evaluate(CreateEvent("R084", SeverityLevel.High), descriptor, tuning, new DateTime(2026, 4, 28, 12, 0, 0, DateTimeKind.Utc));
        var noisyDecision = evaluator.Evaluate(CreateEvent("R084", SeverityLevel.High), descriptor, tuning, new DateTime(2026, 4, 28, 12, 10, 0, DateTimeKind.Utc));
        var resetDecision = evaluator.Evaluate(CreateEvent("R084", SeverityLevel.High), descriptor, tuning, new DateTime(2026, 4, 28, 13, 11, 0, DateTimeKind.Utc));

        Assert.Equal(RuleNoiseBudgetDisposition.Shadowed, noisyDecision.Disposition);
        Assert.Equal(RuleNoiseBudgetDisposition.Allowed, resetDecision.Disposition);
    }

    [Fact]
    public void Critical_Events_Bypass_Budgets_Only_When_Configured()
    {
        var descriptor = Descriptor("R084");
        var tuning = RuleTuningCatalog.Resolve("SmallBusiness", descriptor, CreateEvent("R084", SeverityLevel.Critical), CreateRecord());
        var allowBypass = new RuleNoiseBudgetEvaluator(new RuleNoiseBudgetStore(new Dictionary<string, RuleNoiseBudget>
        {
            ["R084"] = new(MaxAlertsPerRulePerHour: 0, MaxAlertsPerHostPerRulePerHour: 0, MaxShadowEventsPerRulePerHour: 1, AllowCriticalBypass: true)
        }));
        var denyBypass = new RuleNoiseBudgetEvaluator(new RuleNoiseBudgetStore(new Dictionary<string, RuleNoiseBudget>
        {
            ["R084"] = new(MaxAlertsPerRulePerHour: 0, MaxAlertsPerHostPerRulePerHour: 0, MaxShadowEventsPerRulePerHour: 1, AllowCriticalBypass: false)
        }));

        var bypassed = allowBypass.Evaluate(CreateEvent("R084", SeverityLevel.Critical), descriptor, tuning, new DateTime(2026, 4, 28, 12, 0, 0, DateTimeKind.Utc));
        var notBypassed = denyBypass.Evaluate(CreateEvent("R084", SeverityLevel.Critical), descriptor, tuning, new DateTime(2026, 4, 28, 12, 0, 0, DateTimeKind.Utc));

        Assert.Equal(RuleNoiseBudgetDisposition.Bypassed, bypassed.Disposition);
        Assert.NotEqual(RuleNoiseBudgetDisposition.Bypassed, notBypassed.Disposition);
    }

    private static RuleDescriptor Descriptor(string ruleId)
        => RuleCatalog.Find(ruleId) ?? throw new InvalidOperationException($"Missing descriptor for {ruleId}.");

    private static DetectionEvent CreateEvent(string ruleId, SeverityLevel severity)
        => new()
        {
            RuleId = ruleId,
            RuleName = Descriptor(ruleId).Name,
            ConfidenceScore = 0.98,
            Description = "Synthetic alert candidate",
            Summary = "Synthetic alert candidate",
            Evidence = "Synthetic alert candidate",
            TimestampUtc = new DateTime(2026, 4, 28, 12, 0, 0, DateTimeKind.Utc),
            SourceIp = "10.0.0.10",
            DestinationIp = "203.0.113.20",
            DestinationPort = 443,
            Protocol = "HTTP",
            Severity = severity
        };

    private static TrafficRecord CreateRecord()
        => new()
        {
            Source = "10.0.0.10",
            Destination = "203.0.113.20",
            DestinationPort = 443,
            Protocol = "HTTP",
            Info = "GET / HTTP/1.1",
            HttpHost = "example.test",
            HttpUri = "/",
            ApplicationProtocol = "HTTP",
            ApplicationService = "HTTP",
            IsTcp = true
        };
}
