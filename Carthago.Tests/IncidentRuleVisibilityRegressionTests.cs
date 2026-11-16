// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Run on the pinned Windows build before promotion.
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Analytics.Models;
using Carthago.Models;
using Carthago.Services;
using Carthago.Views;
using Xunit;

namespace Carthago.Tests;

public sealed class IncidentRuleVisibilityRegressionTests
{
    [Fact]
    public void Persisted_Rule_And_Event_References_Survive_Incident_ViewModel_RoundTrip()
    {
        // Persisted incidents may contain identifiers but no embedded DetectionEvent.
        var original = new Incident
        {
            PrimaryRuleId = "R102",
            RelatedRuleIds = new List<string> { "R102", "R118" },
            RelatedEventIds = new List<string> { "event-102", "event-118" },
            CorrelationReason = "Stored correlation",
            EvidenceSummary = "Recorded IDs only"
        };

        var vm = IncidentVm.From(original);
        var restored = vm.ToModel();

        Assert.Equal("R102", restored.PrimaryRuleId);
        Assert.Equal(new[] { "R102", "R118" }, restored.RelatedRuleIds);
        Assert.Equal(new[] { "event-102", "event-118" }, restored.RelatedEventIds);
        Assert.Equal("Stored correlation", restored.CorrelationReason);
        Assert.Equal("Recorded IDs only", restored.EvidenceSummary);
        Assert.Equal(new[] { "R102", "R118" }, IncidentQueueProjectionService.GetRecordedRuleIds(restored));
        Assert.Contains("R102", vm.RuleIds);
        Assert.Contains("R118", vm.RuleIds);
        Assert.Empty(restored.RelatedEvents);
    }

    [Fact]
    public void Projection_Uses_Only_Explicit_References_From_All_Recorded_Incident_Sources()
    {
        var incident = new Incident
        {
            PrimaryRuleId = "R102",
            RelatedRuleIds = new List<string> { "r102", " R118 ", " " },
            RelatedEvents = new List<DetectionEvent>
            {
                new() { RuleId = "R163" },
                new() { RuleId = "r118" }
            },
            RelatedAnomalies = new List<AnomalySignal>
            {
                new() { RelatedRuleIds = new List<string> { "R275", "R163" } }
            },
            Title = "R999 appears in title only",
            RiskScore = 100
        };

        Assert.Equal(new[] { "R102", "R118", "R163", "R275" },
            IncidentQueueProjectionService.GetRecordedRuleIds(incident));
    }

    [Fact]
    public void No_Incident_References_Does_Not_Fabricate_A_Detected_Rule()
    {
        var incident = new Incident
        {
            Title = "Potential R001 scan",
            Summary = "Anomaly model raised concern about 198.51.100.5",
            PrimarySourceIp = "198.51.100.5",
            RiskScore = 100
        };

        Assert.Empty(IncidentQueueProjectionService.GetRecordedRuleIds(incident));
        Assert.Empty(IncidentQueueProjectionService.GetRecordedRuleIds(null));
        Assert.Empty(IncidentQueueProjectionService.GetRecordedRuleIds(incident, 0));
    }

    [Fact]
    public void Projection_Uses_Stable_Order_And_Bounds_The_Visible_Result()
    {
        var incident = new Incident
        {
            RelatedRuleIds = Enumerable.Range(1, 30).Select(i => $"R{i:000}").ToList()
        };

        Assert.Equal(8, IncidentQueueProjectionService.GetRecordedRuleIds(incident).Count);
        Assert.Equal(new[] { "R001", "R002", "R003" },
            IncidentQueueProjectionService.GetRecordedRuleIds(incident, 3));
    }
}
