// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Net;
using Carthago.Engine;
using Carthago.Models;
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

public sealed class ActiveFindingQualificationTests : IDisposable
{
    private static readonly Guid Adapter = Guid.Parse("02702701-1234-4321-9999-000000000001");
    private static readonly IPAddress Source = IPAddress.Parse("192.168.1.20"), Target = IPAddress.Parse("192.168.1.1");
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 0, 0, 0, TimeSpan.Zero);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "carthago-finding-" + Guid.NewGuid().ToString("N"));
    private DateTimeOffset _now = Now;
    private ActiveEvidenceStore Store() => new(Path.Combine(_dir, "active.db"), clock: () => _now);
    private static ActiveEvidenceRow Dns(DateTimeOffset t, string address, DnsIntegrityStatus status = DnsIntegrityStatus.AnswersObserved) =>
        ActiveEvidenceProjection.From(Adapter, new DnsIntegrityObservation(Source, Target, "lab.example", status,
            new[] { address }, 0, t, TimeSpan.Zero, null));
    private static ActiveEvidenceRow Tcp(DateTimeOffset t, TcpExposureStatus status) =>
        ActiveEvidenceProjection.From(Adapter, TcpExposureSensor.DefaultPorts.Select(p =>
            new TcpExposureObservation(Source, Target, p, p == 443 ? status : TcpExposureStatus.Refused, t, TimeSpan.Zero, null)).ToArray());

    [Fact]
    public void TwoDistinctChangesProduceOnePersistedDetectionAndReplayDoesNotDuplicate()
    {
        var baseline = Dns(Now.AddHours(-1), "192.0.2.1");
        Assert.True(Store().Save(baseline)); Assert.True(Store().Approve(baseline.Id));
        _now = Now.AddMinutes(5);
        var first = Dns(_now, "192.0.2.2");
        Assert.True(Store().Save(first)); Assert.Empty(Store().ReadFindings().Rows);
        _now = Now.AddMinutes(10);
        var second = Dns(_now, "192.0.2.2");
        Assert.True(Store().Save(second));
        var finding = Assert.Single(Store().ReadFindings().Rows);
        Assert.Equal("ASD003", finding.RuleId);
        Assert.Equal(baseline.Id, finding.BaselineId);
        Assert.Equal(first.Id, finding.FirstObservationId);
        Assert.Equal(second.Id, finding.ConfirmingObservationId);
        var evt = ActiveFindingQualification.ToDetection(finding);
        Assert.Equal(finding.Id, evt.EventId);
        Assert.Equal(SeverityLevel.Low, evt.Severity);
        Assert.Equal(DetectionConfidenceLabel.Medium, evt.ConfidenceLabel);
        Assert.Equal(DetectionDeliveryStatus.Persisted, evt.DeliveryStatus);
        Assert.Null(evt.PacketId); Assert.Null(evt.FlowId);
        Assert.Contains(evt.StructuredEvidence!.Items, x => x.Key == "Origin" && x.Value == "ActiveProbe");
        Assert.False(Store().Save(second));
        _now = Now.AddMinutes(15);
        Assert.True(Store().Save(Dns(_now, "192.0.2.2")));
        Assert.Equal(finding.Id, Assert.Single(Store().ReadFindings().Rows).Id);
        Assert.Empty(Store().ReadFindings(ActiveSensorKind.Tcp).Rows);
        Assert.Empty(Store().ReadFindings(target: "192.168.1.2").Rows);
    }

    [Fact]
    public void NoApprovalNoFinding()
    {
        Assert.True(Store().Save(Dns(Now.AddHours(-1), "192.0.2.1")));
        Assert.True(Store().Save(Dns(Now.AddMinutes(-5), "192.0.2.2")));
        Assert.True(Store().Save(Dns(Now, "192.0.2.2")));
        Assert.Empty(Store().ReadFindings().Rows);
    }

    [Theory]
    [InlineData("recovery")]
    [InlineData("timeout")]
    [InlineData("different")]
    public void InterveningObservationBreaksConfirmation(string intervening)
    {
        var baseline = Dns(Now.AddHours(-1), "192.0.2.1");
        Assert.True(Store().Save(baseline)); Assert.True(Store().Approve(baseline.Id));
        _now = Now.AddMinutes(5);
        Assert.True(Store().Save(Dns(_now, "192.0.2.2")));
        _now = Now.AddMinutes(10);
        Assert.True(Store().Save(Dns(_now, intervening == "recovery" ? "192.0.2.1" : "192.0.2.3",
            intervening == "timeout" ? DnsIntegrityStatus.TimedOut : DnsIntegrityStatus.AnswersObserved)));
        _now = Now.AddMinutes(15);
        Assert.True(Store().Save(Dns(_now, "192.0.2.2")));
        Assert.Empty(Store().ReadFindings().Rows);
    }

    [Theory]
    [InlineData("same-id")]
    [InlineData("too-close")]
    [InlineData("too-old")]
    [InlineData("future")]
    [InlineData("before-approval")]
    [InlineData("different-scope")]
    [InlineData("different-change")]
    public void QualificationRejectsInvalidConfirmation(string change)
    {
        var baseline = Dns(Now.AddDays(-2), "192.0.2.1");
        var first = Dns(Now.AddMinutes(-5), "192.0.2.2");
        var current = Dns(Now, "192.0.2.2");
        long approved = Now.AddDays(-1).UtcDateTime.Ticks;
        switch (change)
        {
            case "same-id": current.Id = first.Id; break;
            case "too-close": first.ObservedTicks = Now.AddSeconds(-30).UtcDateTime.Ticks; break;
            case "too-old": first.ObservedTicks = Now.AddHours(-25).UtcDateTime.Ticks; approved = baseline.ObservedTicks; break;
            case "future": current.ObservedTicks = Now.AddMinutes(1).UtcDateTime.Ticks; break;
            case "before-approval": approved = Now.AddMinutes(-1).UtcDateTime.Ticks; break;
            case "different-scope": current.AdapterId = Guid.NewGuid().ToString("D"); break;
            case "different-change": current = Dns(Now, "192.0.2.3"); break;
        }
        Assert.Empty(ActiveFindingQualification.Qualify(baseline, first, current, approved, Now));
    }

    [Fact]
    public void TcpOpenIsMediumInvestigationNotAttackAttribution()
    {
        var baseline = Tcp(Now.AddHours(-1), TcpExposureStatus.Refused);
        var first = Tcp(Now.AddMinutes(-5), TcpExposureStatus.Open);
        var current = Tcp(Now, TcpExposureStatus.Open);
        var finding = Assert.Single(ActiveFindingQualification.Qualify(baseline, first, current,
            Now.AddMinutes(-10).UtcDateTime.Ticks, Now));
        Assert.Equal("ASD001", finding.RuleId);
        Assert.Equal(SeverityLevel.Medium, ActiveFindingQualification.ToDetection(finding).Severity);
        Assert.Equal("TCP 443", finding.Field);
        Assert.Empty(ActiveFindingQualification.Qualify(baseline, first, Tcp(Now, TcpExposureStatus.TimedOut),
            Now.AddMinutes(-10).UtcDateTime.Ticks, Now));
    }

    [Fact]
    public void ApprovalDoesNotBackfillAndFindingsExpire()
    {
        var baseline = Dns(Now.AddHours(-1), "192.0.2.1");
        Assert.True(Store().Save(baseline));
        Assert.True(Store().Save(Dns(Now.AddMinutes(-10), "192.0.2.2")));
        Assert.True(Store().Save(Dns(Now.AddMinutes(-5), "192.0.2.2")));
        Assert.True(Store().Approve(baseline.Id));
        Assert.Empty(Store().ReadFindings().Rows);
        _now = Now.AddMinutes(5);
        Assert.True(Store().Save(Dns(_now, "192.0.2.2")));
        Assert.Empty(Store().ReadFindings().Rows);
        _now = Now.AddMinutes(10);
        Assert.True(Store().Save(Dns(_now, "192.0.2.2")));
        Assert.Single(Store().ReadFindings().Rows);
        _now = Now.AddDays(31);
        Assert.Empty(Store().ReadFindings().Rows);
    }


    [Fact]
    public void LateContradictoryObservationCannotRewriteConfirmedSequence()
    {
        var baseline = Dns(Now.AddHours(-1), "192.0.2.1");
        Assert.True(Store().Save(baseline)); Assert.True(Store().Approve(baseline.Id));
        _now = Now.AddMinutes(5);
        Assert.True(Store().Save(Dns(_now, "192.0.2.2")));
        _now = Now.AddMinutes(10);
        Assert.True(Store().Save(Dns(_now, "192.0.2.2")));
        var finding = Assert.Single(Store().ReadFindings().Rows);
        Assert.False(Store().Save(Dns(Now.AddMinutes(7), "192.0.2.1")));
        Assert.False(Store().Save(Dns(_now, "192.0.2.1")));
        Assert.Equal(finding.Id, Assert.Single(Store().ReadFindings().Rows).Id);
        Assert.Equal(3, Store().Read().Rows.Count);
    }

    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }
}
