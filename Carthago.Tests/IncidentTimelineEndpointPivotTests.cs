// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Contract authored first; Windows execution is owner-deferred.
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Analytics.Models;
using Carthago.Views;
using Xunit;

namespace Carthago.Tests;

public sealed class IncidentTimelineEndpointPivotTests
{
    [Theory]
    [InlineData("Detection")]
    [InlineData("Anomaly")]
    [InlineData("MlSignal")]
    public void Recorded_Network_Observations_Expose_Exact_Ip_Queries_Without_Requiring_Event_Links(string type)
    {
        var row = TimelineItemVm.From(new IncidentTimelineItem
        {
            Type = type,
            SourceIp = "198.51.100.7",
            DestinationIp = "203.0.113.14",
            DestinationHost = "api.example.test"
        }, new HashSet<string>());

        Assert.False(row.CanInvestigateExactEvent);
        Assert.True(row.HasEndpointInvestigations);
        Assert.True(row.CanInvestigateSource);
        Assert.True(row.CanInvestigateDestination);
        Assert.Equal("198.51.100.7", row.SourceInvestigationQuery);
        // An exact recorded destination IP takes precedence over a broad hostname text search.
        Assert.Equal("203.0.113.14", row.DestinationInvestigationQuery);
    }

    [Fact]
    public void Dns_Destination_Is_Offered_Only_Without_A_Valid_Destination_Ip()
    {
        var row = TimelineItemVm.From(new IncidentTimelineItem
        {
            Type = "Anomaly", DestinationIp = "not-an-ip", DestinationHost = "gateway.example.test"
        }, new HashSet<string>());

        Assert.False(row.CanInvestigateSource);
        Assert.True(row.CanInvestigateDestination);
        Assert.Equal("gateway.example.test", row.DestinationInvestigationQuery);
    }

    [Theory]
    [InlineData("event:foreign-id")]
    [InlineData("port:443")]
    [InlineData("unknown destination")]
    [InlineData("bad host with spaces")]
    [InlineData("https://example.test/path")]
    public void Free_Text_Is_Not_Turned_Into_An_Explorer_Command(string malformedHost)
    {
        var row = TimelineItemVm.From(new IncidentTimelineItem
        {
            Type = "Detection", SourceIp = "not-an-ip", DestinationIp = "not-an-ip",
            DestinationHost = malformedHost
        }, new HashSet<string>());

        Assert.False(row.HasEndpointInvestigations);
        Assert.False(row.CanInvestigateSource);
        Assert.False(row.CanInvestigateDestination);
        Assert.Equal(string.Empty, row.SourceInvestigationQuery);
        Assert.Equal(string.Empty, row.DestinationInvestigationQuery);
    }

    [Theory]
    [InlineData("127.1")]
    [InlineData("42")]
    [InlineData("0x7f000001")]
    [InlineData("010.0.0.1")]
    public void Noncanonical_Ipv4_Shorthand_Does_Not_Become_A_Different_Search_Address(string ambiguousIp)
    {
        var row = TimelineItemVm.From(new IncidentTimelineItem
        {
            Type = "Detection", SourceIp = ambiguousIp,
            DestinationIp = ambiguousIp, DestinationHost = ambiguousIp
        }, new HashSet<string>());

        Assert.False(row.HasEndpointInvestigations);
    }

    [Theory]
    [InlineData("Summary")]
    [InlineData("RiskChange")]
    [InlineData("StatusChange")]
    [InlineData("Feedback")]
    public void Generated_Case_Context_Does_Not_Masquerade_As_An_Observed_Network_Endpoint(string type)
    {
        var row = TimelineItemVm.From(new IncidentTimelineItem
        {
            Type = type, SourceIp = "198.51.100.8", DestinationIp = "203.0.113.9"
        }, new HashSet<string>());

        Assert.False(row.HasEndpointInvestigations);
        Assert.Empty(row.SourceInvestigationQuery);
        Assert.Empty(row.DestinationInvestigationQuery);
    }

    [Fact]
    public void Filtered_Timeline_Still_Carries_Only_Visible_Recorded_Endpoint_Actions()
    {
        var incident = new Incident
        {
            TimelineItems = new List<IncidentTimelineItem>
            {
                new() { Type = "Detection", Title = "Recorded network observation", SourceIp = "192.0.2.10" },
                new() { Type = "Summary", Title = "Generated case story", SourceIp = "192.0.2.11" }
            }
        };
        var vm = IncidentVm.From(incident);
        vm.ApplyTimelineFilters("Detections", "Entire case");

        Assert.Equal(2, vm.TimelineItems.Count);
        var visible = Assert.Single(vm.VisibleTimelineItems);
        Assert.Equal("192.0.2.10", visible.SourceInvestigationQuery);
        Assert.Equal("Recorded network observation", visible.Title);
        Assert.False(vm.TimelineItems.Single(item => item.Title == "Generated case story").HasEndpointInvestigations);
    }
}
