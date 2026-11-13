// SPDX-License-Identifier: MIT
using System.Text.Json;
using Carthago.Models;
using Carthago.Engine.Rules;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableDetectionModelTests
{
    [Fact]
    public void SinglePortableAssemblyOwnsDetectionTypes()
    {
        var assembly = typeof(TrafficRecord).Assembly;
        Assert.Equal("Carthago.Core", assembly.GetName().Name);
        foreach (var type in new[] { typeof(DetectionEvent), typeof(DetectionEvidenceSet),
            typeof(SeverityLevel), typeof(Sensitivity), typeof(RuleDescriptor),
            typeof(RuleEvaluationResult), typeof(RuleNoMatchReason), typeof(RuleMode) })
            Assert.Same(assembly, type.Assembly);
        Assert.DoesNotContain(assembly.GetReferencedAssemblies(), r =>
            r.Name is "Carthago" or "PresentationFramework" or "PresentationCore" or "WindowsBase");
    }

    [Fact]
    public void SerializationPreservesEvidenceAndSeparateDeliveryStates()
    {
        var time = new DateTime(2026, 11, 13, 12, 0, 0, DateTimeKind.Utc);
        var evt = new DetectionEvent { RuleId = "R001", TimestampUtc = time,
            Severity = SeverityLevel.High, DeliveryStatus = DetectionDeliveryStatus.Persisted,
            ExternalDeliveryStatus = ExternalSinkDeliveryStatus.Failed,
            StructuredEvidence = new(new[] { new DetectionEvidenceItem("port", "443", "fixture") }, "fixture") };
        var restored = JsonSerializer.Deserialize<DetectionEvent>(JsonSerializer.Serialize(evt))!;
        Assert.Equal(evt.EventId, restored.EventId);
        Assert.Equal(time, restored.TimestampUtc);
        Assert.Equal(SeverityLevel.High, restored.Severity);
        Assert.Equal(DetectionDeliveryStatus.Persisted, restored.DeliveryStatus);
        Assert.Equal(ExternalSinkDeliveryStatus.Failed, restored.ExternalDeliveryStatus);
        Assert.Equal("443", Assert.Single(restored.StructuredEvidence!.Items).Value);
    }

    [Fact]
    public void OutcomesDoNotConfuseMatchMissingDisabledSuppressedOrFailed()
    {
        var evt = new DetectionEvent { RuleId = "R001" };
        Assert.Same(evt, Assert.Single(RuleEvaluationResult.Match("R001", evt).Events));
        var missing = RuleEvaluationResult.NoMatch("R001", RuleNoMatchReasonCategory.MissingTelemetry, "MISSING", "fixture");
        Assert.True(missing.Evaluated);
        Assert.False(missing.Matched);
        Assert.Equal(RuleNoMatchReasonCategory.MissingTelemetry, Assert.Single(missing.NoMatchReasons).Category);
        var disabled = RuleEvaluationResult.SkippedDisabled("R001");
        Assert.True(disabled.Skipped);
        Assert.False(disabled.Evaluated);
        var suppressed = RuleEvaluationResult.SuppressedMatch("R001");
        Assert.True(suppressed.Matched && suppressed.Suppressed);
        var failed = RuleEvaluationResult.FailedRule("R001", "fixture");
        Assert.True(failed.Evaluated && failed.Failed);
        foreach (var result in new[] { missing, disabled, suppressed, failed })
            Assert.Empty(result.Events);
    }

    [Fact]
    public void NewEventDoesNotClaimPersistence()
    {
        var evt = new DetectionEvent();
        Assert.Equal(DetectionDeliveryStatus.Pending, evt.DeliveryStatus);
        Assert.Equal(ExternalSinkDeliveryStatus.NotQueued, evt.ExternalDeliveryStatus);
        Assert.Null(evt.PersistedAtUtc);
        Assert.Equal(Sensitivity.Balanced, evt.SensitivityAtTrigger);
    }
}
