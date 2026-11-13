// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

public sealed class ActiveChangeDetectorTests : IDisposable
{
    private static readonly Guid Adapter = Guid.Parse("02702701-1234-4321-9999-000000000001");
    private static readonly IPAddress Source = IPAddress.Parse("192.168.1.20"), Target = IPAddress.Parse("192.168.1.1");
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 0, 0, 0, TimeSpan.Zero);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "carthago-change-" + Guid.NewGuid().ToString("N"));
    private ActiveEvidenceStore Store(DateTimeOffset? now = null) => new(Path.Combine(_dir, "active.db"), clock: () => now ?? Now);
    private static ActiveEvidenceRow Dns(DateTimeOffset t, DnsIntegrityStatus status, params string[] addresses) =>
        ActiveEvidenceProjection.From(Adapter, new DnsIntegrityObservation(Source, Target, "lab.example", status,
            addresses, 0, t, TimeSpan.Zero, null));
    private static ActiveEvidenceRow Tcp(DateTimeOffset t, TcpExposureStatus status) =>
        ActiveEvidenceProjection.From(Adapter, TcpExposureSensor.DefaultPorts.Select(p =>
            new TcpExposureObservation(Source, Target, p, p == 443 ? status : TcpExposureStatus.Refused, t, TimeSpan.Zero, null)).ToArray());
    private static ActiveEvidenceRow Gateway(DateTimeOffset t, GatewayIntegrityStatus status, params string[] macs) =>
        ActiveEvidenceProjection.From(Adapter, new GatewayIntegrityObservation(Source, Target, status, macs, null, false, null, false, t));
    private static ActiveEvidenceRow Tls(DateTimeOffset t, TlsInspectionStatus status, string hash, SslPolicyErrors errors) =>
        ActiveEvidenceProjection.From(Adapter, new TlsInspectionObservation(Source, Target, 443, "lab.example", status,
            new TlsCertificateEvidence("subject", "issuer", "serial", hash, Now.AddDays(-1), Now.AddDays(1), "WithinValidityPeriod",
                null, null, errors, Array.Empty<X509ChainStatusFlags>(), null), null, null, t, TimeSpan.Zero));
    private static ActiveEvidenceRow Http(DateTimeOffset t, int code, params HttpHeaderEvidence[] headers) =>
        ActiveEvidenceProjection.From(Adapter, new HttpHealthObservation(Source, Target, 443, "lab.example", true,
            HttpHealthStatus.ResponseObserved, code, headers, HttpRedirectScope.NotRedirect, null, t, TimeSpan.Zero));
    private static ActiveEvidenceRow Snmp(DateTimeOffset t, SnmpInfrastructureStatus status, int? count, uint uptime) =>
        ActiveEvidenceProjection.From(Adapter, new SnmpInfrastructureObservation(Source, Target, status,
            new SnmpInfrastructureEvidence("desc", "1.3.6.1.4.1.9", uptime, "name", count), t, TimeSpan.Zero));

    [Fact]
    public void ApprovalPersistsAndIsNeverImplicit()
    {
        var before = Dns(Now.AddHours(-1), DnsIntegrityStatus.AnswersObserved, "192.0.2.1");
        var after = Dns(Now, DnsIntegrityStatus.AnswersObserved, "192.0.2.2");
        Assert.True(Store().Save(before)); Assert.True(Store().Save(after));
        Assert.Equal("NoApprovedBaseline", Store().CompareApproved(after.Id).Status);
        Assert.True(Store().Approve(before.Id));
        Assert.Equal("DnsAnswerChanged", Assert.Single(Store().CompareApproved(after.Id).Changes).Kind);
        Assert.True(Store().Approve(after.Id));
        Assert.Equal("Incomparable", Store().CompareApproved(after.Id).Status);
    }

    [Fact]
    public void ExpiredApprovalCannotBeUsed()
    {
        var before = Dns(Now.AddDays(-29), DnsIntegrityStatus.AnswersObserved, "192.0.2.1");
        var after = Dns(Now, DnsIntegrityStatus.AnswersObserved, "192.0.2.2");
        Assert.True(Store().Save(before)); Assert.True(Store().Save(after)); Assert.True(Store().Approve(before.Id));
        Assert.Equal("NoApprovedBaseline", Store(Now.AddDays(2)).CompareApproved(after.Id).Status);
    }

    [Theory]
    [InlineData("adapter")]
    [InlineData("source")]
    [InlineData("target")]
    [InlineData("probe")]
    [InlineData("origin")]
    [InlineData("time")]
    public void UnrelatedOrOlderEvidenceRejected(string change)
    {
        var a = Dns(Now.AddMinutes(-1), DnsIntegrityStatus.AnswersObserved, "192.0.2.1");
        var b = Dns(Now, DnsIntegrityStatus.AnswersObserved, "192.0.2.2");
        switch (change)
        {
            case "adapter": b.AdapterId = Guid.NewGuid().ToString("D"); break;
            case "source": b.Source = "192.168.1.21"; break;
            case "target": b.Target = "192.168.1.2"; break;
            case "probe": b.ProbeKey = "other.example"; break;
            case "origin": b.Origin = "Passive"; break;
            case "time": b.ObservedTicks = a.ObservedTicks; break;
        }
        Assert.Equal("Incomparable", ActiveChangeDetector.Compare(a, b).Status);
    }

    [Fact]
    public void TcpOnlyDefiniteTransitionsProduceChanges()
    {
        var a = Tcp(Now.AddMinutes(-1), TcpExposureStatus.Refused);
        var b = Tcp(Now, TcpExposureStatus.Open);
        Assert.Equal("PortOpened", Assert.Single(ActiveChangeDetector.Compare(a, b).Changes).Kind);
        Assert.Equal("PortRefused", Assert.Single(ActiveChangeDetector.Compare(Tcp(Now.AddMinutes(-1), TcpExposureStatus.Open),
            Tcp(Now, TcpExposureStatus.Refused)).Changes).Kind);
        Assert.Empty(ActiveChangeDetector.Compare(a, Tcp(Now, TcpExposureStatus.TimedOut)).Changes);
    }

    [Fact]
    public void DnsSetOrderIgnoredAndTimeoutNotChange()
    {
        var a = Dns(Now.AddMinutes(-1), DnsIntegrityStatus.AnswersObserved, "192.0.2.1", "192.0.2.2");
        Assert.Equal("NoChangeObserved", ActiveChangeDetector.Compare(a,
            Dns(Now, DnsIntegrityStatus.AnswersObserved, "192.0.2.2", "192.0.2.1")).Status);
        Assert.Equal("Inconclusive", ActiveChangeDetector.Compare(a, Dns(Now, DnsIntegrityStatus.TimedOut)).Status);
        Assert.False(ActiveChangeDetector.EligibleBaseline(Dns(Now, DnsIntegrityStatus.TimedOut)));
    }

    [Fact]
    public void TlsReplacementAndPolicyChangeAreSeparate()
    {
        var a = Tls(Now.AddMinutes(-1), TlsInspectionStatus.Authenticated, new string('a', 64), SslPolicyErrors.None);
        var b = Tls(Now, TlsInspectionStatus.CertificateRejected, new string('b', 64), SslPolicyErrors.RemoteCertificateNameMismatch);
        var changes = ActiveChangeDetector.Compare(a, b).Changes;
        Assert.Contains(changes, c => c.Kind == "CertificateChanged");
        Assert.Contains(changes, c => c.Kind == "CertificatePolicyChanged");
        Assert.False(ActiveChangeDetector.EligibleBaseline(b));
        Assert.Equal("Inconclusive", ActiveChangeDetector.Compare(a, Tls(Now, TlsInspectionStatus.HandshakeFailed,
            new string('b', 64), SslPolicyErrors.None)).Status);
    }

    [Fact]
    public void HttpHeaderRemovalOnlyComparedOnSuccess()
    {
        var a = Http(Now.AddMinutes(-1), 200, new HttpHeaderEvidence("Strict-Transport-Security", new[] { "max-age=123" }));
        Assert.Equal("HttpHeaderChanged", Assert.Single(ActiveChangeDetector.Compare(a, Http(Now, 200)).Changes).Kind);
        Assert.Equal("HttpStatusChanged", Assert.Single(ActiveChangeDetector.Compare(a, Http(Now, 503)).Changes).Kind);
    }

    [Fact]
    public void GatewayConflictAndCacheOnlyAreDifferent()
    {
        const string a = "02:00:00:00:00:01", b = "02:00:00:00:00:02";
        var baseline = Gateway(Now.AddMinutes(-1), GatewayIntegrityStatus.Observed, a);
        Assert.Equal("GatewayCompetingClaims", Assert.Single(ActiveChangeDetector.Compare(baseline,
            Gateway(Now, GatewayIntegrityStatus.ConflictingClaims, a, b)).Changes).Kind);
        Assert.Equal("Inconclusive", ActiveChangeDetector.Compare(baseline, Gateway(Now, GatewayIntegrityStatus.NoReply)).Status);
    }

    [Fact]
    public void SnmpUptimeAndUnknownValuesDoNotCreateInventoryChange()
    {
        var a = Snmp(Now.AddMinutes(-1), SnmpInfrastructureStatus.Observed, 24, 1000);
        Assert.Empty(ActiveChangeDetector.Compare(a, Snmp(Now, SnmpInfrastructureStatus.Partial, null, 1)).Changes);
        Assert.Equal("InterfaceCount", Assert.Single(ActiveChangeDetector.Compare(a,
            Snmp(Now, SnmpInfrastructureStatus.Observed, 48, 1)).Changes).Field);
        Assert.Equal("Inconclusive", ActiveChangeDetector.Compare(a, Snmp(Now, SnmpInfrastructureStatus.AgentReport, 48, 1)).Status);
    }

    [Fact]
    public void InvalidBaselineAndMalformedCurrentAreRejected()
    {
        var a = Dns(Now.AddMinutes(-1), DnsIntegrityStatus.AnswersObserved, "192.0.2.1");
        var b = Dns(Now, DnsIntegrityStatus.AnswersObserved, "192.0.2.2");
        b.EvidenceJson = "not-json";
        Assert.Equal("Incomparable", ActiveChangeDetector.Compare(a, b).Status);
        var timeout = Dns(Now, DnsIntegrityStatus.TimedOut);
        Assert.True(Store().Save(timeout));
        Assert.False(Store().Approve(timeout.Id));
    }

    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }
}
