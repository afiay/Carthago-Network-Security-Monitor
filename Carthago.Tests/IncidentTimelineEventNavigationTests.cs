// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Tests authored before implementation; owner-deferred Windows execution.
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Analytics.Models;
using Carthago.Analytics.Services;
using Carthago.Models;
using Carthago.Views;
using Xunit;

namespace Carthago.Tests;

public sealed class IncidentTimelineEventNavigationTests
{
    [Fact]
    public void Builder_Records_Original_Detection_Event_Id_In_Timeline_Details()
    {
        var incident = new Incident { Id = "incident-timeline-id" };
        var detection = new DetectionEvent
        {
            EventId = "exact-event-17", RuleId = "R017", Description = "Recorded detection",
            Timestamp = new DateTime(2026, 11, 10, 10, 0, 0, DateTimeKind.Utc)
        };

        new IncidentTimelineBuilder().AddDetection(incident, detection);

        Assert.Equal("exact-event-17", Assert.Single(incident.TimelineItems).Details["EventId"]);
    }

    [Fact]
    public void Selected_Case_Enables_Only_Its_Own_Explicit_Detection_Chronology_Links()
    {
        var detection = new DetectionEvent { EventId = "case-event", RuleId = "R110", Timestamp = DateTime.UtcNow };
        var incident = new Incident { RelatedEvents = new List<DetectionEvent> { detection } };
        new IncidentTimelineBuilder().AddDetection(incident, detection);
        incident.TimelineItems.Add(new IncidentTimelineItem
        {
            Type = "Anomaly", Title = "Not a detection", Details = new Dictionary<string, string> { ["EventId"] = "case-event" }
        });
        incident.TimelineItems.Add(new IncidentTimelineItem
        {
            Type = "Detection", Title = "Unrelated", Details = new Dictionary<string, string> { ["EventId"] = "foreign-event" }
        });
        incident.TimelineItems.Add(new IncidentTimelineItem { Type = "Detection", Title = "Legacy no ID" });

        var timeline = IncidentVm.From(incident).TimelineItems;

        Assert.Single(timeline.Where(item => item.CanInvestigateExactEvent));
        Assert.Equal("case-event", timeline.Single(item => item.CanInvestigateExactEvent).ExactEventId);
        Assert.False(timeline.Single(item => item.Title == "Not a detection").CanInvestigateExactEvent);
        Assert.False(timeline.Single(item => item.Title == "Unrelated").CanInvestigateExactEvent);
        Assert.False(timeline.Single(item => item.Title == "Legacy no ID").CanInvestigateExactEvent);
    }

    [Fact]
    public void Recorded_Id_Without_Embedded_Detection_Can_Resolve_An_Explicit_Timeline_Link()
    {
        var incident = new Incident
        {
            RelatedEventIds = new List<string> { "persisted-id" },
            TimelineItems = new List<IncidentTimelineItem>
            {
                new() { Type = "Detection", Details = new Dictionary<string, string> { ["EventId"] = "persisted-id" } }
            }
        };

        Assert.Equal("persisted-id", Assert.Single(IncidentVm.From(incident).TimelineItems).ExactEventId);
    }

    [Fact]
    public void Noncanonical_Timeline_Id_Is_Never_Treated_As_An_Exact_Link()
    {
        var incident = new Incident
        {
            RelatedEventIds = new List<string> { "original-event" },
            TimelineItems = new List<IncidentTimelineItem>
            {
                new() { Type = "Detection", Details = new Dictionary<string, string> { ["EventId"] = " original-event " } }
            }
        };

        Assert.False(Assert.Single(IncidentVm.From(incident).TimelineItems).CanInvestigateExactEvent);
    }

    [Fact]
    public void Existing_Chronology_Dedup_Does_Not_Remove_Recorded_Case_Id_Fallbacks()
    {
        var timestamp = new DateTime(2026, 11, 10, 10, 0, 0, DateTimeKind.Utc);
        var incident = new Incident { Id = "same-story" };
        var builder = new IncidentTimelineBuilder();
        builder.AddDetection(incident, new DetectionEvent
        {
            EventId = "first-id", RuleId = "R100", Description = "Same summary", Timestamp = timestamp
        });
        builder.AddDetection(incident, new DetectionEvent
        {
            EventId = "second-id", RuleId = "R100", Description = "Same summary", Timestamp = timestamp
        });
        incident.RelatedEventIds.AddRange(new[] { "first-id", "second-id" });

        // The existing stable story key intentionally coalesces these entries.
        Assert.Single(incident.TimelineItems);
        Assert.Equal("first-id", incident.TimelineItems[0].Details["EventId"]);
        Assert.Equal(2, IncidentDetectionLinkVm.FromIncident(incident).Count(link => link.CanInvestigate));
    }
}
