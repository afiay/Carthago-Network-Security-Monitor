// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Contract authored first; Windows execution is owner-deferred.
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Analytics.Models;
using Carthago.Views;
using Xunit;

namespace Carthago.Tests;

public sealed class IncidentTimelineTimeWindowTests
{
    private static readonly DateTime HistoricalAnchor = new(2021, 4, 5, 14, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Relative_Windows_Use_Latest_Recorded_Event_Not_Current_Clock()
    {
        var vm = IncidentVm.From(WithTimeline(
            Entry("Outside", "Detection", HistoricalAnchor.AddHours(-25)),
            Entry("Yesterday", "Detection", HistoricalAnchor.AddHours(-24)),
            Entry("Hour boundary", "Anomaly", HistoricalAnchor.AddHours(-1)),
            Entry("Recent", "Detection", HistoricalAnchor.AddMinutes(-15)),
            Entry("Anchor", "RiskChange", HistoricalAnchor)));

        vm.ApplyTimelineWindow("Last hour");
        Assert.Equal(new[] { "Hour boundary", "Recent", "Anchor" }, Titles(vm));
        Assert.Equal(5, vm.TimelineItems.Count);
        Assert.Equal("Last hour", vm.TimelineWindow);
        Assert.Contains("2021-04-05 14:00:00 UTC", vm.TimelineWindowContext);

        vm.ApplyTimelineWindow("Last 24 hours");
        Assert.Equal(new[] { "Yesterday", "Hour boundary", "Recent", "Anchor" }, Titles(vm));

        vm.ApplyTimelineWindow("Last 15 minutes");
        Assert.Equal(new[] { "Recent", "Anchor" }, Titles(vm));

        vm.ApplyTimelineWindow("Last 7 days");
        Assert.Equal(5, vm.VisibleTimelineItems.Count);
    }

    [Fact]
    public void Activity_And_Time_Filters_Intersect_Using_The_Full_Case_Anchor()
    {
        var vm = IncidentVm.From(WithTimeline(
            Entry("Old detection", "Detection", HistoricalAnchor.AddMinutes(-70)),
            Entry("New detection", "Detection", HistoricalAnchor.AddMinutes(-30)),
            Entry("Latest risk", "RiskChange", HistoricalAnchor)));

        vm.ApplyTimelineFilters("Detections", "Last hour");
        Assert.Equal(new[] { "New detection" }, Titles(vm));
        Assert.Equal(3, vm.TimelineItems.Count);
        Assert.Contains("1 of 3", vm.TimelineFilterSummary);

        vm.ApplyTimelineFilter("Risk changes");
        Assert.Equal("Last hour", vm.TimelineWindow);
        Assert.Equal(new[] { "Latest risk" }, Titles(vm));

        vm.ApplyTimelineWindow("Entire case");
        Assert.Equal("Risk changes", vm.TimelineFilter);
        Assert.Equal(new[] { "Latest risk" }, Titles(vm));

        vm.ApplyTimelineFilters("All activity", "Entire case");
        Assert.Equal(3, vm.VisibleTimelineItems.Count);
    }

    [Fact]
    public void Selected_Windows_Recalculate_On_Live_Case_Update()
    {
        var vm = IncidentVm.From(WithTimeline(
            Entry("Initial detection", "Detection", HistoricalAnchor.AddMinutes(-10))));
        vm.ApplyTimelineFilters("Detections", "Last 15 minutes");

        vm.UpdateFrom(WithTimeline(
            Entry("Initial detection", "Detection", HistoricalAnchor.AddMinutes(-10)),
            Entry("Later risk", "RiskChange", HistoricalAnchor.AddMinutes(20))));

        Assert.Equal("Detections", vm.TimelineFilter);
        Assert.Equal("Last 15 minutes", vm.TimelineWindow);
        Assert.Empty(vm.VisibleTimelineItems);
        Assert.True(vm.HasNoMatchingTimelineItems);
        Assert.Contains("0 of 2", vm.TimelineFilterSummary);
        Assert.Equal(2, vm.TimelineItems.Count);
    }

    [Fact]
    public void Undated_Records_Are_Kept_In_The_Full_Story_But_Not_Relative_Windows()
    {
        var vm = IncidentVm.From(WithTimeline(
            Entry("No timestamp", "Detection", default),
            Entry("Dated", "Detection", HistoricalAnchor)));

        vm.ApplyTimelineWindow("Last hour");
        Assert.Equal(new[] { "Dated" }, Titles(vm));
        Assert.Equal(2, vm.TimelineItems.Count);

        vm.ApplyTimelineWindow("Invalid window");
        Assert.Equal("Entire case", vm.TimelineWindow);
        Assert.Equal(2, vm.VisibleTimelineItems.Count);

        var undated = IncidentVm.From(WithTimeline(Entry("No timestamp", "Detection", default)));
        undated.ApplyTimelineWindow("Last hour");
        Assert.True(undated.HasNoMatchingTimelineItems);
        Assert.Contains("No valid recorded timestamps", undated.TimelineWindowContext);

        var empty = IncidentVm.From(WithTimeline());
        Assert.Single(empty.VisibleTimelineItems);
        Assert.True(empty.VisibleTimelineItems[0].IsEmptyState);
    }

    private static Incident WithTimeline(params IncidentTimelineItem[] entries)
        => new() { TimelineItems = new List<IncidentTimelineItem>(entries) };

    private static IncidentTimelineItem Entry(string title, string type, DateTime timestampUtc)
        => new() { Title = title, Type = type, TimestampUtc = timestampUtc };

    private static string[] Titles(IncidentVm vm)
        => vm.VisibleTimelineItems.Select(item => item.Title).ToArray();
}
