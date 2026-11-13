// SPDX-License-Identifier: MIT
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Contracts;
using Carthago.Services;
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

public sealed class ActiveAuthorizationSurveillanceTests : IDisposable
{
    private static readonly Guid AdapterId = Guid.Parse("02702701-1234-4321-9999-000000000001");
    private static readonly LocalLanInterface Adapter = new("lab", IPAddress.Parse("192.168.50.10"), IPAddress.Parse("255.255.255.0"));
    private static readonly IPAddress Target = IPAddress.Parse("192.168.50.11");
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "carthago-surveillance-" + Guid.NewGuid().ToString("N"));
    private DateTimeOffset _now = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);
    private long _timestamp;
    private SnmpCredentialVault Vault() => new(Path.Combine(_dir, "vault.db"));
    private ActiveSensorProfileStore Store() => new(Path.Combine(_dir, "profiles.db"), () => _now, Vault());
    private static SnmpCredentialScope Scope() => SnmpCredentialScope.Create(AdapterId, Adapter, Target);
    private static ActiveSensorProfile Profile(string host = "lab.example", bool snmp = false) =>
        ActiveSensorProfile.Create(AdapterId, Adapter, Target, snmp ? ActiveSensorKind.Snmp : ActiveSensorKind.Dns,
            snmp ? "" : host, snmp ? 161 : 53, TimeSpan.FromHours(24), true);
    private ActiveExecutionGrant Grant(ActiveSensorProfile p, TimeSpan? lifetime = null)
    {
        Assert.True(Store().Save(p));
        Guid? generation = p.Kind == ActiveSensorKind.Snmp
            ? Vault().Save(Scope(), new SnmpCredential("lab-user", "authphrase", "privphrase")) : null;
        return Assert.IsType<ActiveExecutionGrant>(Store().Grant(p, lifetime ?? TimeSpan.FromHours(1), generation));
    }
    private void AdvancePoll() => _timestamp += Stopwatch.Frequency * 5;
    private static string Reservation() => @"Global\Carthago.Test.ActiveScheduler." + Guid.NewGuid().ToString("N");

    [Theory]
    [InlineData("revoke")]
    [InlineData("replace")]
    [InlineData("expire")]
    [InlineData("rotate")]
    public async Task IdleGrantInvalidationBlocksWithoutNewProbeOrEvidence(string mode)
    {
        var p = Profile(snmp: mode == "rotate");
        var grant = Grant(p);
        string name = Reservation();
        int probes = 0, writes = 0;
        ActiveSensorRun Result() { probes++; return new("Observed", true, new ActiveEvidenceRow()); }
        var manager = new ActiveSensorManager(() => _now, _ => Adapter,
            (_, _, _) => Task.FromResult(Result()), _ => { writes++; return true; },
            acquireReservation: () => WindowsActiveSchedulerReservation.AcquireNamed(name),
            snmpProbe: (_, _, _, _) => Task.FromResult(Result()), timestamp: () => _timestamp);
        manager.AddAuthorized(p, Store(), grant.GrantId);
        ActiveSensorScheduleState? prior = null;
        using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await manager.RunAsync(cancel.Token, stopWhenAllBlocked: true, sample: () =>
        {
            var current = Assert.Single(manager.Snapshot());
            if (probes != 1 || prior is not null) return;
            prior = current;
            Assert.True(current.NextDueUtc > _now);
            switch (mode)
            {
                case "revoke": Assert.True(Store().Revoke(grant.Id)); break;
                case "replace": Assert.NotNull(Store().Grant(p, TimeSpan.FromHours(1))); break;
                case "expire": _now = _now.AddHours(1); break;
                case "rotate": Assert.NotNull(Vault().Save(Scope(), new SnmpCredential("lab-user", "newauthphrase", "newprivphrase"))); break;
            }
            AdvancePoll();
        });
        Assert.NotNull(prior);
        var blocked = Assert.Single(manager.Snapshot());
        Assert.True(blocked.ScopeBlocked);
        Assert.Equal(DateTimeOffset.MaxValue, blocked.NextDueUtc);
        Assert.Equal(prior!.LastRunUtc, blocked.LastRunUtc);
        Assert.Equal(prior.HistoryStatus, blocked.HistoryStatus);
        Assert.Equal(prior.CompletedProbes, blocked.CompletedProbes);
        Assert.Equal(prior.ResponsiveProbes, blocked.ResponsiveProbes);
        Assert.Equal(1, probes); Assert.Equal(1, writes);
        Assert.False(manager.HasReservation);
        using var successor = WindowsActiveSchedulerReservation.AcquireNamed(name);
    }

    [Fact]
    public async Task PartialRevocationPreservesOtherProfileAndNeverResurrectsOldBinding()
    {
        var a = Profile(); var b = Profile("other.example");
        var ga = Grant(a); var gb = Grant(b);
        string name = Reservation();
        int probes = 0, writes = 0, phase = 0;
        var manager = new ActiveSensorManager(() => _now, _ => Adapter,
            (_, _, _) => { probes++; return Task.FromResult(new ActiveSensorRun("Observed", true, new ActiveEvidenceRow())); },
            _ => { writes++; return true; }, acquireReservation: () => WindowsActiveSchedulerReservation.AcquireNamed(name),
            timestamp: () => _timestamp);
        manager.AddAuthorized(a, Store(), ga.GrantId);
        manager.AddAuthorized(b, Store(), gb.GrantId);
        using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => manager.RunAsync(cancel.Token, stopWhenAllBlocked: true,
            sample: () =>
            {
                var states = manager.Snapshot();
                if (phase == 0 && probes == 2)
                {
                    Assert.True(Store().Revoke(ga.Id)); AdvancePoll(); phase = 1;
                }
                else if (phase == 1 && states.Single(s => s.Profile.Id == a.Id).ScopeBlocked)
                {
                    Assert.False(states.Single(s => s.Profile.Id == b.Id).ScopeBlocked);
                    Assert.NotNull(Store().Grant(a, TimeSpan.FromHours(1)));
                    AdvancePoll(); phase = 2;
                }
                else if (phase == 2)
                {
                    Assert.True(states.Single(s => s.Profile.Id == a.Id).ScopeBlocked);
                    Assert.False(states.Single(s => s.Profile.Id == b.Id).ScopeBlocked);
                    phase = 3; cancel.Cancel();
                }
            }));
        Assert.Equal(3, phase); Assert.Equal(2, probes); Assert.Equal(2, writes);
        Assert.False(manager.HasReservation);
        using var successor = WindowsActiveSchedulerReservation.AcquireNamed(name);
    }

    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }
}
