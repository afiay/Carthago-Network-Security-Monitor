// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Tests authored first; Windows test execution is owner-deferred.
using System;
using System.Collections.Generic;
using Carthago.Analytics.Models;
using Carthago.Models;
using Carthago.Views;
using Xunit;

namespace Carthago.Tests;

public sealed class IncidentDetectionLinkVmTests
{
    [Fact]
    public void Uses_Only_Recorded_Event_Identifiers_And_Deduplicates_Case_References()
    {
        var incident = new Incident
        {
            RelatedEvents = new List<DetectionEvent>
            {
                new() { EventId = "evt-1", RuleId = "R021", Description = "Observed request", Timestamp = new DateTime(2026, 11, 10, 12, 0, 0, DateTimeKind.Utc) }
            },
            RelatedEventIds = new List<string> { "EVT-1", "evt-2" }
        };

        var links = IncidentDetectionLinkVm.FromIncident(incident);

        Assert.Equal(2, links.Count);
        Assert.Equal("evt-1", links[0].EventId);
        Assert.True(links[0].CanInvestigate);
        Assert.Equal("R021", links[0].RuleLabel);
        Assert.Equal("evt-2", links[1].EventId);
        Assert.Equal("Detection ID recorded; event details not attached to this case.", links[1].Description);
    }

    [Fact]
    public void Keeps_Missing_Or_Invalid_Event_Ids_Visible_But_Not_Navigable()
    {
        var incident = new Incident
        {
            RelatedEvents = new List<DetectionEvent>
            {
                new() { EventId = "", RuleId = "R002", Description = "No ID" },
                new() { EventId = new string('x', 129), RuleId = "R003", Description = "Invalid ID" },
                new() { EventId = "evt-4 ", RuleId = "R004", Description = "Noncanonical ID" }
            },
            RelatedEventIds = new List<string> { " ", "id\nunsafe" }
        };

        var links = IncidentDetectionLinkVm.FromIncident(incident);

        Assert.Equal(3, links.Count);
        Assert.All(links, link => Assert.False(link.CanInvestigate));
        Assert.All(links, link => Assert.Equal("Exact event ID unavailable", link.EventIdLabel));
    }

    [Fact]
    public void Bounds_Link_List_To_Existing_Incident_Review_Cap()
    {
        var incident = new Incident();
        for (var i = 0; i < 20; i++)
            incident.RelatedEventIds.Add($"evt-{i}");

        Assert.Equal(8, IncidentDetectionLinkVm.FromIncident(incident).Count);
        Assert.Empty(IncidentDetectionLinkVm.FromIncident(new Incident()));
    }

    [Fact]
    public void Valid_Recorded_Ids_Take_Priority_Over_Unnavigable_Case_Rows()
    {
        var incident = new Incident();
        for (var i = 0; i < 8; i++)
            incident.RelatedEvents.Add(new DetectionEvent { EventId = "", RuleId = $"R{i:000}" });
        incident.RelatedEventIds.Add("known-id");

        var links = IncidentDetectionLinkVm.FromIncident(incident);

        Assert.Equal(8, links.Count);
        Assert.Contains(links, link => link.CanInvestigate && link.EventId == "known-id");
    }

    [Fact]
    public void Unknown_Timestamp_Kind_Does_Not_Claim_A_Local_Time()
    {
        var incident = new Incident
        {
            RelatedEvents = new List<DetectionEvent>
            {
                new() { EventId = "evt-time", Timestamp = new DateTime(2026, 11, 10, 12, 0, 0, DateTimeKind.Unspecified) }
            }
        };

        Assert.Equal("Time zone not recorded", Assert.Single(IncidentDetectionLinkVm.FromIncident(incident)).TimeLabel);
    }
}
