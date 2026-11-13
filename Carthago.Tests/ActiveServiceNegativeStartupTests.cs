// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Contracts;
using Carthago.Services;
using Carthago.Services.Sensors;
using LiteDB;
using Xunit;

namespace Carthago.Tests;

public sealed class ActiveServiceNegativeStartupTests : IDisposable
{
    private static readonly Guid AdapterId = Guid.Parse("02702701-1234-4321-9999-000000000001");
    private static readonly LocalLanInterface Adapter = new("lab", IPAddress.Parse("192.168.50.10"), IPAddress.Parse("255.255.255.0"));
    private static readonly IPAddress Target = IPAddress.Parse("192.168.50.11");
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "carthago-negative-startup-" + Guid.NewGuid().ToString("N"));
    private DateTimeOffset _now = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);
    private string VaultPath => Path.Combine(_dir, "credentials.db");
    private SnmpCredentialVault Vault() => new(VaultPath);
    private ActiveSensorProfileStore Store() => new(Path.Combine(_dir, "profiles.db"), () => _now, Vault());
    private static ActiveSensorProfile Profile(bool snmp = false) => ActiveSensorProfile.Create(AdapterId, Adapter, Target,
        snmp ? ActiveSensorKind.Snmp : ActiveSensorKind.Dns, snmp ? "" : "lab.example", snmp ? 161 : 53, TimeSpan.FromMinutes(5), true);
    private ActiveExecutionGrant Grant(ActiveSensorProfile p)
    {
        Assert.True(Store().Save(p));
        Guid? generation = null;
        if (p.Kind == ActiveSensorKind.Snmp)
            generation = Vault().Save(SnmpCredentialScope.Create(AdapterId, Adapter, Target),
                new SnmpCredential("lab-user", "authphrase", "privphrase"));
        return Assert.IsType<ActiveExecutionGrant>(Store().Grant(p, TimeSpan.FromHours(1), generation));
    }
    private void CorruptCredential()
    {
        using var db = new LiteDatabase(VaultPath);
        var rows = db.GetCollection<SnmpCredentialVault.Entry>("snmp_credentials");
        var row = rows.FindById(SnmpCredentialScope.Create(AdapterId, Adapter, Target).Key);
        row.ProtectedPayload = new byte[] { 1, 2, 3 };
        Assert.True(rows.Update(row));
    }
    private async Task RejectAsync(ActiveExecutionGrant grant, Action? onAcquire = null,
        Func<Guid, IReadOnlyList<LocalLanInterface>>? resolve = null, bool expectManager = false)
    {
        string name = @"Global\Carthago.Test.ActiveScheduler." + Guid.NewGuid().ToString("N");
        int managers = 0, probes = 0, writes = 0, samples = 0, acquired = 0;
        using var output = new StringWriter(); using var error = new StringWriter();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var run = new ActiveServiceRun((token, ready) =>
        {
            return ActiveSensorWorker.ExecuteCoreAsync(new[] { "run", "--profile", grant.Id },
                output, error, token, Store(), resolve ?? (_ => new[] { Adapter }),
                () =>
                {
                    managers++;
                    return new ActiveSensorManager(() => _now, _ => Adapter,
                        (_, _, _) => { probes++; return Task.FromResult(new ActiveSensorRun("Observed", true, new ActiveEvidenceRow())); },
                        _ => { writes++; return true; },
                        acquireReservation: () => { acquired++; onAcquire?.Invoke(); return WindowsActiveSchedulerReservation.AcquireNamed(name); },
                        snmpProbe: (_, _, _, _) => { probes++; return Task.FromResult(new ActiveSensorRun("Observed", true, new ActiveEvidenceRow())); });
                }, () => _now, pinnedGrants: new Dictionary<string, Guid> { [grant.Id] = grant.GrantId },
                ready: ready, sample: (_, _, _) => samples++);
        });
        using var registration = timeout.Token.Register(run.RequestStop);
        Assert.Equal(3, await run.Completion.WaitAsync(TimeSpan.FromSeconds(15)));
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.Started);
        Assert.Equal(expectManager ? 1 : 0, managers);
        Assert.Equal(expectManager ? 1 : 0, acquired);
        Assert.Equal(0, probes); Assert.Equal(0, writes); Assert.Equal(0, samples);
        using var successor = WindowsActiveSchedulerReservation.AcquireNamed(name);
    }

    [Fact]
    public async Task ExpiredPinnedGrantNeverCreatesManager()
    {
        var grant = Grant(Profile());
        _now = _now.AddHours(1);
        await RejectAsync(grant);
    }

    [Fact]
    public async Task CorruptCredentialMetadataCannotAuthorizeServiceReadiness()
    {
        var p = Profile(true);
        var grant = Grant(p);
        CorruptCredential();
        Assert.True(Store().IsAuthorized(p, grant.GrantId)); // Metadata alone still matches.
        await RejectAsync(grant);
    }

    [Fact]
    public async Task GrantReplacementAtAcquisitionNeverSignalsReadiness()
    {
        var p = Profile();
        var grant = Grant(p);
        await RejectAsync(grant, () => Assert.NotNull(Store().Grant(p, TimeSpan.FromHours(1))), expectManager: true);
    }

    [Fact]
    public async Task CredentialCorruptionAtAcquisitionNeverSignalsReadiness()
    {
        var grant = Grant(Profile(true));
        await RejectAsync(grant, CorruptCredential, expectManager: true);
    }

    [Fact]
    public async Task ScopeLossAtAcquisitionNeverSignalsReadiness()
    {
        var grant = Grant(Profile());
        bool current = true;
        await RejectAsync(grant, () => current = false,
            _ => current ? new[] { Adapter } : Array.Empty<LocalLanInterface>(), expectManager: true);
    }

    [Fact]
    public async Task InitialHealthFailureReleasesReservationWithoutReadiness()
    {
        var p = Profile();
        var grant = Grant(p);
        string name = @"Global\Carthago.Test.ActiveScheduler." + Guid.NewGuid().ToString("N");
        int probes = 0;
        using var output = new StringWriter(); using var error = new StringWriter();
        using var run = new ActiveServiceRun((token, ready) => ActiveSensorWorker.ExecuteCoreAsync(
            new[] { "run", "--profile", grant.Id }, output, error, token, Store(), _ => new[] { Adapter },
            () => new ActiveSensorManager(() => _now, _ => Adapter,
                (_, _, _) => { probes++; return Task.FromResult(new ActiveSensorRun("Observed", true, null)); },
                acquireReservation: () => WindowsActiveSchedulerReservation.AcquireNamed(name)), () => _now,
            pinnedGrants: new Dictionary<string, Guid> { [grant.Id] = grant.GrantId }, ready: ready,
            sample: (_, _, _) => throw new IOException("Injected publication failure")));
        Assert.Equal(3, await run.Completion.WaitAsync(TimeSpan.FromSeconds(15)));
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.Started);
        Assert.Equal(0, probes);
        using var next = WindowsActiveSchedulerReservation.AcquireNamed(name);
    }

    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }
}
