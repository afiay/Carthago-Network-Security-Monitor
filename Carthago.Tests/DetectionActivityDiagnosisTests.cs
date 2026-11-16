// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; deterministic read-only diagnostic tests.
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Health;
using Carthago.Services.Diagnostics;
using Xunit;

namespace Carthago.Tests;

public sealed class DetectionActivityDiagnosisTests
{
    private static RuleRuntimeStats Stats(
        long evaluations = 0,
        long matches = 0,
        long skipped = 0,
        long failures = 0)
        => new("R102", evaluations, matches, Math.Max(0, evaluations - matches),
            0, failures, skipped, 0, 0, 0, 0, null, null, null);

    private static RuleNoMatchStats NoReasons => RuleNoMatchStats.Empty("R102");

    [Fact]
    public void Disabled_Mode_Is_Reported_As_Current_Policy_Even_When_Old_Matches_Exist()
    {
        var diagnosis = DetectionActivityDiagnosis.ForRule(
            Stats(evaluations: 5, matches: 2), RuleMode.Disabled, NoReasons, 0, 0, 0, 2);

        Assert.Equal(RuleActivityState.CurrentlyDisabled, diagnosis.State);
        Assert.Contains("earlier", diagnosis.Explanation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Emitted_Rule_Does_Not_Promise_Alert_Was_Displayed()
    {
        var diagnosis = DetectionActivityDiagnosis.ForRule(
            Stats(evaluations: 5, matches: 2), RuleMode.Alert, NoReasons, 0, 0, 0, 1);

        Assert.Equal(RuleActivityState.Emitted, diagnosis.State);
        Assert.Contains("UI event delivery", diagnosis.NextCheck);
        Assert.DoesNotContain("visible alert confirmed", diagnosis.Explanation, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(2, 0)]
    [InlineData(0, 2)]
    [InlineData(0, 0)]
    public void Matched_But_Not_Emitted_Remains_Distinct_From_No_Match(
        long shadowed, long suppressed)
    {
        var diagnosis = DetectionActivityDiagnosis.ForRule(
            Stats(evaluations: 4, matches: 2), RuleMode.Alert, NoReasons,
            0, shadowed, suppressed, 0);

        Assert.Equal(RuleActivityState.MatchedNotEmitted, diagnosis.State);
        Assert.Contains("emitted: 0", diagnosis.Explanation);
    }

    [Fact]
    public void Evaluation_Failures_Do_Not_Masquerade_As_Benign_No_Matches()
    {
        var diagnosis = DetectionActivityDiagnosis.ForRule(
            Stats(evaluations: 1, failures: 1), RuleMode.Alert, NoReasons, 0, 0, 0, 0);

        Assert.Equal(RuleActivityState.ExecutionFailures, diagnosis.State);
        Assert.Contains("last failure", diagnosis.NextCheck);
    }

    [Fact]
    public void Evaluated_No_Match_Reports_Dominant_Reason_And_Required_Field_Action()
    {
        var reason = new NoMatchReasonAggregate(
            "R102", RuleNoMatchReasonCategory.MissingTelemetry, "MISSING_REQUIRED_TELEMETRY",
            "DNS answers unavailable", 3, DateTime.UtcNow, DateTime.UtcNow,
            new Dictionary<string, string>());
        var noMatch = new RuleNoMatchStats("R102", 3, new[] { reason });

        var diagnosis = DetectionActivityDiagnosis.ForRule(
            Stats(evaluations: 3), RuleMode.Alert, noMatch, 1, 0, 0, 0);

        Assert.Equal(RuleActivityState.EvaluatedNoMatch, diagnosis.State);
        Assert.Contains("MISSING_REQUIRED_TELEMETRY", diagnosis.Explanation);
        Assert.Contains("missing required fields", diagnosis.NextCheck);
    }

    [Fact]
    public void Skipped_Selector_Without_Evaluation_Is_Not_Counted_As_Evaluated()
    {
        var diagnosis = DetectionActivityDiagnosis.ForRule(
            Stats(skipped: 7), RuleMode.Alert, NoReasons, 1, 0, 0, 0);

        Assert.Equal(RuleActivityState.SkippedBeforeEvaluation, diagnosis.State);
        Assert.Contains("7", diagnosis.Explanation);
        Assert.Contains("selector", diagnosis.NextCheck);
    }

    [Fact]
    public void Unobserved_Required_Telemetry_Is_Distinguished_From_A_Rule_Skip()
    {
        var diagnosis = DetectionActivityDiagnosis.ForRule(
            Stats(), RuleMode.Alert, NoReasons, 2, 0, 0, 0);

        Assert.Equal(RuleActivityState.TelemetryUnobserved, diagnosis.State);
        Assert.Contains("not observed", diagnosis.Explanation);
    }

    [Fact]
    public void Completely_Unobserved_Rule_Does_Not_Claim_That_Traffic_Is_Benign()
    {
        var diagnosis = DetectionActivityDiagnosis.ForRule(
            Stats(), RuleMode.Alert, NoReasons, 0, 0, 0, 0);

        Assert.Equal(RuleActivityState.NotObserved, diagnosis.State);
        Assert.Contains("No rule evaluations", diagnosis.Explanation);
        Assert.DoesNotContain("benign", diagnosis.Explanation, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(null, 5, "FIRST SNAPSHOT")]
    [InlineData(5, 5, "NO NEW ENGINE EVALUATIONS")]
    [InlineData(5, 7, "2 new calls")]
    [InlineData(7, 1, "COUNTERS RESET")]
    public void Progress_Uses_Two_Snapshots_Without_Claiming_Rule_Matches(
        long? prior, long current, string expected)
    {
        var progress = DetectionActivityDiagnosis.ForProgress(prior, current);
        Assert.Contains(expected, progress);
        Assert.DoesNotContain("confirmed malicious", progress, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(0, 0, 0, 0, 0, 0, 0, "NO ENGINE EVALUATIONS")]
    [InlineData(1, 0, 0, 0, 0, 0, 0, "NO RULE EVALUATIONS")]
    [InlineData(1, 1, 0, 0, 0, 0, 0, "NO MATCHES")]
    [InlineData(1, 2, 1, 1, 0, 0, 0, "MATCHES WITHOUT EMITTED ALERTS")]
    [InlineData(1, 2, 1, 0, 0, 1, 0, "ALERTS EMITTED")]
    [InlineData(1, 2, 1, 0, 0, 1, 2, "JOURNAL FAILURES")]
    public void Pipeline_Diagnosis_Has_Clear_Stage_And_No_Automatic_Qualification(
        long engine, long evaluations, long matches,
        long shadowed, long suppressed, long emitted, long journalFailures,
        string expected)
    {
        var explanation = DetectionActivityDiagnosis.ForPipeline(
            engine, evaluations, matches, shadowed, suppressed, emitted, journalFailures);

        Assert.Contains(expected, explanation);
        Assert.DoesNotContain("certified", explanation, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("validated", explanation, StringComparison.OrdinalIgnoreCase);
    }
}
