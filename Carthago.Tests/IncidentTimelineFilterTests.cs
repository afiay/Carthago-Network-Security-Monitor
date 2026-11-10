// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Test contract authored first; owner-deferred Windows execution.
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Analytics.Models;
using Carthago.Views;
using Xunit;

namespace Carthago.Tests;

public sealed class IncidentTimelineFilterTests
{
    [Fact]
    public void Timeline_Filter_Groups_Separate_Recorded_Activity_Without_Dropping_The_Full_Story()
    {
        var types = new[]
        {
            "Detection", "Anomaly", "MlSignal", "RiskChange", "Feedback", "Suppression",
            "TrustRule", "StatusChange", "Summary", "RecommendedAction", "DemoStep", "FutureSignal"
        };
        var incident = new Incident
        {
            TimelineItems = types.Select((type, index) => new IncidentTimelineItem
            {
                Id = $"timeline-{index}", Type = type, Title = type,
                TimestampUtc = new DateTime(2026, 11, 10, 10, 0, 0, DateTimeKind.Utc).AddMinutes(index)
            }).ToList()
        };
        var vm = IncidentVm.From(incident);
        Assert.Equal(12, vm.TimelineItems.Count);

        vm.ApplyTimelineFilter("Detections");
        Assert.Equal(new[] { "Detection" }, vm.VisibleTimelineItems.Select(item => item.Title));

        vm.ApplyTimelineFilter("Anomalies");
        Assert.Equal(new[] { "Anomaly", "MlSignal" }, vm.VisibleTimelineItems.Select(item => item.Title));

        vm.ApplyTimelineFilter("Risk changes");
        Assert.Equal(new[] { "RiskChange" }, vm.VisibleTimelineItems.Select(item => item.Title));

        vm.ApplyTimelineFilter("Case actions");
        Assert.Equal(new[] { "Feedback", "Suppression", "TrustRule", "StatusChange" },
            vm.VisibleTimelineItems.Select(item => item.Title));

        vm.ApplyTimelineFilter("Story updates");
        Assert.Equal(new[] { "Summary", "RecommendedAction", "DemoStep" },
            vm.VisibleTimelineItems.Select(item => item.Title));

        vm.ApplyTimelineFilter("Other activity");
        Assert.Equal(new[] { "FutureSignal" }, vm.VisibleTimelineItems.Select(item => item.Title));

        vm.ApplyTimelineFilter("All activity");
        Assert.Equal(types, vm.VisibleTimelineItems.Select(item => item.Title));
        Assert.Equal(12, vm.TimelineItems.Count);
    }

    [Fact]
    public void Active_Filter_Remains_Consistent_After_Incident_Is_Updated()
    {
        var first = new Incident
        {
            TimelineItems = new List<IncidentTimelineItem>
            {
                new() { Type = "Detection", Title = "Original detection" }
            }
        };
        var vm = IncidentVm.From(first);
        vm.ApplyTimelineFilter("Detections");
        vm.UpdateFrom(new Incident
        {
            TimelineItems = new List<IncidentTimelineItem>
            {
                new() { Type = "Anomaly", Title = "New anomaly" },
                new() { Type = "Detection", Title = "New detection" }
            }
        });

        Assert.Equal("Detections", vm.TimelineFilter);
        Assert.Equal("New detection", Assert.Single(vm.VisibleTimelineItems).Title);
        Assert.Equal(2, vm.TimelineItems.Count);
    }

    [Fact]
    public void Empty_Filter_Matches_Show_An_Honest_Empty_State()
    {
        var vm = IncidentVm.From(new Incident
        {
            TimelineItems = new List<IncidentTimelineItem>
            {
                new() { Type = "RiskChange", Title = "Risk reassessed" }
            }
        });
        vm.ApplyTimelineFilter("Detections");

        Assert.Empty(vm.VisibleTimelineItems);
        Assert.True(vm.HasNoMatchingTimelineItems);
        Assert.Contains("0 of 1", vm.TimelineFilterSummary);

        vm.ApplyTimelineFilter("Unexpected filter");
        Assert.Equal("All activity", vm.TimelineFilter);
        Assert.False(vm.HasNoMatchingTimelineItems);
    }
}
