// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Net;
using Carthago.Analytics.Models;
using Carthago.Analytics.Services;
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

public sealed class ActiveIncidentContextTests : IDisposable
{
    private static readonly Guid Adapter = Guid.Parse("02702701-1234-4321-9999-000000000001");
    private static readonly DateTimeOffset Initial = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "carthago-context-" + Guid.NewGuid().ToString("N"));
    private DateTimeOffset _now = Initial;
    private ActiveEvidenceStore Store() => new(Path.Combine(_dir, "active.db"), clock: () => _now);
    private static ActiveEvidenceRow Row(DateTimeOffset time, string target, string name, string answer) =>
        ActiveEvidenceProjection.From(Adapter, new DnsIntegrityObservation(IPAddress.Parse("192.168.50.10"),
            IPAddress.Parse(target), name, DnsIntegrityStatus.AnswersObserved, new[] { answer }, 0, time, TimeSpan.Zero, null));
    private static Incident Case(string? source = "192.168.50.11", string? destination = "192.168.50.12") =>
        new() { Id = "case-test", PrimarySourceIp = source, PrimaryDestinationIp = destination,
            FirstSeenUtc = Initial.UtcDateTime, LastSeenUtc = Initial.AddMinutes(15).UtcDateTime,
            RiskScore = 42, Severity = "medium", OccurrenceCount = 3 };
    private void Generate(string target, string name, DateTimeOffset baselineTime)
    {
        _now = baselineTime;
        var baseline = Row(_now, target, name, "192.0.2.1");
        Assert.True(Store().Save(baseline)); Assert.True(Store().Approve(baseline.Id));
        _now = baselineTime.AddMinutes(5);
        Assert.True(Store().Save(Row(_now, target, name, "192.0.2.2")));
        _now = baselineTime.AddMinutes(10);
        Assert.True(Store().Save(Row(_now, target, name, "192.0.2.2")));
    }

    [Fact]
    public void BothRecordedEndpointsMatchButProbeSourceAndOtherTargetsDoNot()
    {
        Generate("192.168.50.11", "a.example", Initial);
        Generate("192.168.50.12", "b.example", Initial);
        Generate("192.168.50.13", "c.example", Initial);
        var incident = Case();
        var scope = Assert.IsType<ActiveIncidentScope>(ActiveIncidentContext.CreateScope(incident));
        var result = ActiveIncidentContext.Read(scope, Store());
        Assert.Null(result.Error);
        Assert.Equal(new[] { "192.168.50.11", "192.168.50.12" }, result.Rows.Select(r => r.Target).OrderBy(x => x));
        var probeSource = Assert.IsType<ActiveIncidentScope>(ActiveIncidentContext.CreateScope(Case("192.168.50.10", null)));
        Assert.Empty(ActiveIncidentContext.Read(probeSource, Store()).Rows);
        Assert.Equal(42, incident.RiskScore);
        Assert.Equal(3, incident.OccurrenceCount);
        Assert.Empty(incident.RelatedEvents);
        Assert.Empty(incident.RelatedEventIds);
        Assert.Empty(incident.TimelineItems);
    }

    [Fact]
    public void RecordedObservationRangeExcludesEarlierAndLaterFindings()
    {
        Generate("192.168.50.11", "early.example", Initial.AddMinutes(-20));
        Generate("192.168.50.11", "inside.example", Initial);
        Generate("192.168.50.11", "late.example", Initial.AddMinutes(10));
        var scope = Assert.IsType<ActiveIncidentScope>(ActiveIncidentContext.CreateScope(Case()));
        Assert.Equal("inside.example", Assert.Single(ActiveIncidentContext.Read(scope, Store()).Rows).ProbeKey);
    }

    [Theory]
    [InlineData("demo")]
    [InlineData("public")]
    [InlineData("hostname")]
    [InlineData("unspecified")]
    [InlineData("reversed")]
    public void UnsupportedIncidentContextRejected(string change)
    {
        var incident = Case();
        switch (change)
        {
            case "demo": incident.Tags.Add("demo:example"); break;
            case "public": incident.PrimarySourceIp = "8.8.8.8"; incident.PrimaryDestinationIp = null; break;
            case "hostname": incident.PrimarySourceIp = "lab.example"; incident.PrimaryDestinationIp = null; break;
            case "unspecified": incident.FirstSeenUtc = DateTime.SpecifyKind(incident.FirstSeenUtc, DateTimeKind.Unspecified); break;
            case "reversed": incident.LastSeenUtc = incident.FirstSeenUtc.AddMinutes(-1); break;
        }
        Assert.Null(ActiveIncidentContext.CreateScope(incident));
    }

    [Fact]
    public void TimeFilterRunsBeforeLimitAndSameEndpointIsDeduplicated()
    {
        Generate("192.168.50.11", "inside.example", Initial);
        Generate("192.168.50.11", "newer.example", Initial.AddMinutes(20));
        var incident = Case("192.168.50.11", "192.168.50.11");
        var scope = Assert.IsType<ActiveIncidentScope>(ActiveIncidentContext.CreateScope(incident));
        Assert.Single(scope.Targets);
        var result = Store().ReadFindings(target: "192.168.50.11", limit: 1,
            fromUtc: scope.FromUtc, throughUtc: scope.ThroughUtc);
        Assert.Equal("inside.example", Assert.Single(result.Rows).ProbeKey);
        Assert.Single(ActiveIncidentContext.Read(scope, Store()).Rows);
    }

    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }
}
