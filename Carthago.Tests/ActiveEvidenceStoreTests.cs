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

public sealed class ActiveEvidenceStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "carthago-active-" + Guid.NewGuid().ToString("N"));
    private string PathName => Path.Combine(_dir, "active.db");
    private static readonly Guid Adapter = Guid.Parse("02702701-1234-4321-9999-000000000001");
    private static readonly IPAddress Source = IPAddress.Parse("192.168.1.20");
    private static readonly IPAddress Target = IPAddress.Parse("192.168.1.1");
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 0, 0, 0, TimeSpan.Zero);
    private ActiveEvidenceStore Store(int capacity = 5000, DateTimeOffset? now = null) =>
        new(PathName, capacity, () => now ?? Now);
    private static ActiveEvidenceRow Dns(DateTimeOffset time, string target = "192.168.1.1") =>
        ActiveEvidenceProjection.From(Adapter, new DnsIntegrityObservation(Source, IPAddress.Parse(target),
            "lab.example", DnsIntegrityStatus.AnswersObserved, new[] { "192.0.2.1" }, 0, time, TimeSpan.Zero, null));

    [Fact]
    public void RoundTripAndDuplicateIdCannotRewrite()
    {
        var row = Dns(Now);
        Assert.True(Store().Save(row));
        row.Status = "Changed";
        Assert.False(Store().Save(row));
        var actual = Assert.Single(Store().Read().Rows);
        Assert.Equal("AnswersObserved", actual.Status);
        Assert.Equal("ActiveProbe", actual.Origin);
        Assert.Equal(Adapter.ToString("D"), actual.AdapterId);
        Assert.Equal(row.Id, actual.Id);
    }

    [Fact]
    public void RetentionPrunesOldestAndExpired()
    {
        var store = Store(2);
        Assert.True(store.Save(Dns(Now.AddDays(-29))));
        Assert.True(store.Save(Dns(Now.AddDays(-2))));
        Assert.True(store.Save(Dns(Now)));
        Assert.Equal(2, store.Read().Rows.Count);
        Assert.Equal(Now.UtcDateTime.Ticks, store.Read().Rows[0].ObservedTicks);
        Assert.Empty(Store(2, Now.AddDays(31)).Read().Rows);
    }

    [Fact]
    public void FilterAppliedBeforeLimit()
    {
        Assert.True(Store().Save(Dns(Now.AddMinutes(-2), "192.168.1.2")));
        Assert.True(Store().Save(Dns(Now, "192.168.1.3")));
        Assert.Equal("192.168.1.2", Assert.Single(Store().Read(ActiveSensorKind.Dns, "192.168.1.2", 1).Rows).Target);
        Assert.Empty(Store().Read(ActiveSensorKind.Tls).Rows);
        Assert.NotNull(Store().Read(target: "8.8.8.8").Error);
    }

    [Theory]
    [InlineData("origin")]
    [InlineData("version")]
    [InlineData("adapter")]
    [InlineData("target")]
    [InlineData("payload")]
    [InlineData("future")]
    [InlineData("expired")]
    public void InvalidEvidenceRejected(string change)
    {
        var row = Dns(Now);
        switch (change)
        {
            case "origin": row.Origin = "Passive"; break;
            case "version": row.Version = 2; break;
            case "adapter": row.AdapterId = ""; break;
            case "target": row.Target = "8.8.8.8"; break;
            case "payload": row.EvidenceJson = "{\"x\":\"" + new string('x', 17000) + "\"}"; break;
            case "future": row.ObservedTicks = Now.AddHours(1).Ticks; break;
            case "expired": row.ObservedTicks = Now.AddDays(-31).Ticks; break;
        }
        Assert.False(Store().Save(row));
        Assert.Empty(Store().Read().Rows);
    }

    [Fact]
    public void BackdatedInsertCannotEvictNewerHistory()
    {
        var store = Store(1);
        Assert.True(store.Save(Dns(Now)));
        Assert.False(store.Save(Dns(Now.AddDays(-1))));
        Assert.Equal(Now.Ticks, Assert.Single(store.Read().Rows).ObservedTicks);
    }

    [Fact]
    public void StorageFailureIsExplicitAndDoesNotCreateSuccess()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "blocked"), "file");
        var store = new ActiveEvidenceStore(Path.Combine(_dir, "blocked", "active.db"), clock: () => Now);
        Assert.False(store.Save(Dns(Now)));
    }

    [Fact]
    public void AllSixProjectionsExcludeSensitiveFreeText()
    {
        var tcp = ActiveEvidenceProjection.From(Adapter, TcpExposureSensor.DefaultPorts.Select(p =>
            new TcpExposureObservation(Source, Target, p, TcpExposureStatus.Open, Now, TimeSpan.Zero, null)).ToArray());
        var cert = new TlsCertificateEvidence("private-subject", "private-issuer", "serial", new string('a', 64),
            Now, Now.AddDays(1), "WithinValidityPeriod", "private-san", "DnsSanObserved",
            SslPolicyErrors.None, Array.Empty<X509ChainStatusFlags>(), null);
        var tls = ActiveEvidenceProjection.From(Adapter, new TlsInspectionObservation(Source, Target, 443, "lab.example",
            TlsInspectionStatus.Authenticated, cert, "Tls13", "cipher", Now, TimeSpan.Zero));
        var http = ActiveEvidenceProjection.From(Adapter, new HttpHealthObservation(Source, Target, 443, "lab.example",
            true, HttpHealthStatus.ResponseObserved, 200, new[] { new HttpHeaderEvidence("Server", new[] { "private-banner" }) },
            HttpRedirectScope.NotRedirect, cert, Now, TimeSpan.Zero));
        var gateway = ActiveEvidenceProjection.From(Adapter, new GatewayIntegrityObservation(Source, Target,
            GatewayIntegrityStatus.Observed, new[] { "02:00:00:00:00:01" }, null, false, null, false, Now));
        var snmp = ActiveEvidenceProjection.From(Adapter, new SnmpInfrastructureObservation(Source, Target,
            SnmpInfrastructureStatus.Observed, new("private-description", "1.3.6.1.4.1.9", 123, "private-name", 24),
            Now, TimeSpan.Zero));
        var rows = new[] { tcp, Dns(Now), tls, http, gateway, snmp };
        Assert.Equal(6, rows.Select(r => r.Sensor).Distinct().Count());
        foreach (var row in rows)
        {
            Assert.DoesNotContain("private-", row.EvidenceJson);
            Assert.True(Store().Save(row));
        }
        Assert.Equal(6, Store().Read().Rows.Count);
    }

    [Fact]
    public void IncompleteTcpBatchRejected() =>
        Assert.Throws<ArgumentException>(() => ActiveEvidenceProjection.From(Adapter, Array.Empty<TcpExposureObservation>()));

    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }
}
