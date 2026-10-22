using Carthago.Engine.PayloadNormalization;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Tests;

public sealed class PayloadNormalizationTests
{
    [Fact]
    public void FromTrafficRecord_Decodes_Obfuscated_Quoted_Payloads()
    {
        var record = new TrafficRecord
        {
            HttpMethod = "GET",
            HttpUri = "%24%7Bupper%3AJ%7D%24%7Blower%3An%7D%24%7Bupper%3AD%7D%24%7Blower%3Ai%7D:%2F%2Fexample.com%5Cpath%60'\"",
            HttpUserAgent = "UnitTestAgent"
        };

        var payload = PayloadNormalizer.FromTrafficRecord(record);

        Assert.Equal(record.HttpUri, payload.SourceFragments["http.uri"]);
        Assert.Contains("jndi://example.com/path", payload.LowerInvariant, StringComparison.Ordinal);
        Assert.DoesNotContain("`", payload.Normalized, StringComparison.Ordinal);
        Assert.DoesNotContain("\"", payload.Normalized, StringComparison.Ordinal);
    }

    [Fact]
    public void Match_Sets_Matched_State_And_Preserves_Events()
    {
        var evt = new DetectionEvent
        {
            RuleId = "RTEST",
            Description = "Synthetic detection",
            Severity = SeverityLevel.High,
            TimestampUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
        };

        var result = RuleEvaluationResult.Match("RTEST", evt);

        Assert.True(result.Evaluated);
        Assert.True(result.Matched);
        Assert.False(result.Suppressed);
        Assert.False(result.Failed);
        Assert.Single(result.Events);
        Assert.Same(evt, result.Events[0]);
    }

    [Fact]
    public void Match_List_Uses_Empty_Array_When_Given_Null()
    {
        var result = RuleEvaluationResult.Match("RTEST", events: null!);

        Assert.True(result.Evaluated);
        Assert.True(result.Matched);
        Assert.Empty(result.Events);
    }
}
