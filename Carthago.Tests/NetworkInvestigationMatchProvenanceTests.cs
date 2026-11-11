// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED: Windows xUnit execution owner-deferred.
using Carthago.Analytics.Models;
using Carthago.Models;
using Carthago.Views;
using Xunit;

namespace Carthago.Tests;

public sealed class NetworkInvestigationMatchProvenanceTests
{
    [Fact]
    public void Traffic_Text_Returns_All_Matching_Recorded_Fields_Without_Values()
    {
        var row = new TrafficRecord { HttpHost = "alpha.example", DnsQname = "alpha.example", Info = "alpha.example" };
        Assert.Equal(new[] { "HTTP host", "DNS question" },
            NetworkInvestigationPage.TrafficMatchFields(row, "ALPHA"));
    }

    [Fact]
    public void Exact_Port_And_Ip_Only_Report_Exact_Endpoint_Fields()
    {
        var row = new TrafficRecord { Source = "192.0.2.1", Destination = "192.0.2.1", SourcePort = 443, DestinationPort = 443 };
        Assert.Equal(new[] { "Source IP (exact)", "Destination IP (exact)" },
            NetworkInvestigationPage.TrafficMatchFields(row, "192.0.2.1"));
        Assert.Equal(new[] { "Source port (exact)", "Destination port (exact)" },
            NetworkInvestigationPage.TrafficMatchFields(row, "port:443"));
        Assert.Empty(NetworkInvestigationPage.TrafficMatchFields(row, "event:abc"));
    }

    [Fact]
    public void Empty_And_Unmatched_Queries_Have_No_Provenance()
    {
        Assert.Empty(NetworkInvestigationPage.TrafficMatchFields(new TrafficRecord { DnsQname = "example.test" }, ""));
        Assert.Empty(NetworkInvestigationPage.TrafficMatchFields(new TrafficRecord { DnsQname = "example.test" }, "missing"));
    }

    [Fact]
    public void Detection_Matches_Distinct_Fields_But_Not_Freeform_Evidence()
    {
        var row = new DetectionEvent { RuleId = "R777", RuleName = "R777 finding" };
        Assert.Equal(new[] { "Rule ID", "Rule name" },
            NetworkInvestigationPage.DetectionMatchFields(row, "r777"));
    }

    [Fact]
    public void Detection_Exact_Event_Search_Does_Not_Use_Substring_Matches()
    {
        var row = new DetectionEvent { EventId = "evt-12345", RuleName = "event:evt-123" };
        Assert.Empty(NetworkInvestigationPage.DetectionMatchFields(row, "event:evt-123"));
        Assert.Equal(new[] { "Event ID (exact)" },
            NetworkInvestigationPage.DetectionMatchFields(row, "event:evt-12345"));
    }

    [Fact]
    public void Case_Event_Match_Requires_Recorded_Reference()
    {
        var row = new Incident { Id = "CASE-1", RelatedEventIds = new() { "evt-123" } };
        Assert.Equal(new[] { "Related event ID (exact reference)" },
            NetworkInvestigationPage.IncidentMatchFields(row, "event:evt-123"));
        Assert.Empty(NetworkInvestigationPage.IncidentMatchFields(row, "event:evt-999"));
    }
}
