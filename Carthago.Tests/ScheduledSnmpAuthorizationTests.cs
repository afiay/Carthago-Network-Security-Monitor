// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Carthago.Services;
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

public sealed class ScheduledSnmpAuthorizationTests : IDisposable
{
    private static readonly Guid AdapterId = Guid.Parse("02702701-1234-4321-9999-000000000001");
    private static readonly LocalLanInterface Adapter = new("lab", IPAddress.Parse("192.168.50.10"), IPAddress.Parse("255.255.255.0"));
    private static readonly IPAddress Target = IPAddress.Parse("192.168.50.11");
    private static readonly DateTimeOffset Initial = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "carthago-snmp-schedule-" + Guid.NewGuid().ToString("N"));
    private DateTimeOffset _now = Initial;
    private SnmpCredentialVault Vault() => new(Path.Combine(_dir, "vault.db"));
    private ActiveSensorProfileStore Store() => new(Path.Combine(_dir, "profiles.db"), () => _now, Vault());
    private static SnmpCredentialScope Scope() => SnmpCredentialScope.Create(AdapterId, Adapter, Target);
    private static ActiveSensorProfile Profile() => ActiveSensorProfile.Create(AdapterId, Adapter, Target,
        ActiveSensorKind.Snmp, "", 161, TimeSpan.FromMinutes(5), true);
    private Guid SaveCredential() => Vault().Save(Scope(), new SnmpCredential("lab-user", "authphrase", "privphrase"))!.Value;
    private ActiveExecutionGrant Grant(ActiveSensorProfile p)
    {
        Assert.True(Store().Save(p));
        return Assert.IsType<ActiveExecutionGrant>(Store().Grant(p, TimeSpan.FromHours(1), SaveCredential()));
    }

    [Fact]
    public void ConfigurationAloneCannotScheduleSnmp()
    {
        var p = Profile();
        Assert.True(Store().Save(p));
        Assert.Equal("Snmp", Assert.Single(Store().Read().Rows).Sensor);
        Assert.Null(Store().Grant(p, TimeSpan.FromHours(1)));
        Assert.Throws<InvalidOperationException>(() => new ActiveSensorManager().Add(p));
        Assert.Null(Store().ReadValidGrant(p));
    }

    [Fact]
    public void GrantRequiresExplicitCurrentCredentialGeneration()
    {
        var p = Profile();
        Assert.True(Store().Save(p));
        var first = SaveCredential();
        var second = SaveCredential();
        Assert.Null(Store().Grant(p, TimeSpan.FromHours(1), first));
        Assert.Null(Store().Grant(p, TimeSpan.FromHours(1), Guid.Empty));
        var grant = Assert.IsType<ActiveExecutionGrant>(Store().Grant(p, TimeSpan.FromHours(1), second));
        Assert.Equal(second, grant.CredentialGeneration);
        Assert.Equal("lab-user", Store().LoadAuthorizedSnmp(p, grant.GrantId)?.User);
    }

    [Fact]
    public void RotationAndDeletionInvalidateGrantWithoutResurrection()
    {
        var p = Profile();
        var grant = Grant(p);
        Assert.True(Store().IsAuthorized(p, grant.GrantId));
        var replacement = SaveCredential();
        Assert.False(Store().IsAuthorized(p, grant.GrantId));
        Assert.Null(Store().LoadAuthorizedSnmp(p, grant.GrantId));
        var newGrant = Assert.IsType<ActiveExecutionGrant>(Store().Grant(p, TimeSpan.FromHours(1), replacement));
        Assert.True(Vault().Delete(Scope()));
        Assert.False(Store().IsAuthorized(p, newGrant.GrantId));
        SaveCredential();
        Assert.False(Store().IsAuthorized(p, newGrant.GrantId));
    }

    [Fact]
    public async Task AuthorizedSchedulerUsesOnlyBoundCredentialAndPersistsEvidence()
    {
        var p = Profile();
        var grant = Grant(p);
        int calls = 0, writes = 0;
        var manager = new ActiveSensorManager(() => _now, _ => Adapter,
            probe: (_, _, _) => throw new InvalidOperationException("Generic transport must not run."),
            save: _ => { writes++; return true; },
            snmpProbe: (_, _, secret, _) =>
            {
                Assert.Equal("lab-user", secret.User);
                Assert.Equal("authphrase", secret.Authentication);
                Assert.Equal("privphrase", secret.Privacy);
                calls++;
                return Task.FromResult(new ActiveSensorRun("Observed", true, new ActiveEvidenceRow()));
            });
        manager.AddAuthorized(p, Store(), grant.GrantId);
        Assert.True(await manager.RunDueAsync(default));
        Assert.Equal(1, calls);
        Assert.Equal(1, writes);
        Assert.Equal("Saved", Assert.Single(manager.Snapshot()).HistoryStatus);
    }

    [Fact]
    public async Task RotationBeforeProbeBlocksTransport()
    {
        var p = Profile();
        var grant = Grant(p);
        int calls = 0;
        var manager = new ActiveSensorManager(() => _now, _ => Adapter,
            snmpProbe: (_, _, _, _) => { calls++; return Task.FromResult(new ActiveSensorRun("Observed", true, null)); });
        manager.AddAuthorized(p, Store(), grant.GrantId);
        SaveCredential();
        Assert.True(await manager.RunDueAsync(default));
        Assert.Equal(0, calls);
        Assert.True(Assert.Single(manager.Snapshot()).ScopeBlocked);
    }

    [Fact]
    public async Task RotationDuringProbeSuppressesPersistence()
    {
        var p = Profile();
        var grant = Grant(p);
        int writes = 0;
        var manager = new ActiveSensorManager(() => _now, _ => Adapter,
            save: _ => { writes++; return true; },
            snmpProbe: (_, _, _, _) =>
            {
                SaveCredential();
                return Task.FromResult(new ActiveSensorRun("Observed", true, new ActiveEvidenceRow()));
            });
        manager.AddAuthorized(p, Store(), grant.GrantId);
        Assert.True(await manager.RunDueAsync(default));
        Assert.Equal(0, writes);
        Assert.True(Assert.Single(manager.Snapshot()).ScopeBlocked);
    }

    [Fact]
    public async Task CorruptedCiphertextBlocksBeforeTransport()
    {
        var p = Profile();
        var grant = Grant(p);
        using (var db = new LiteDB.LiteDatabase(Path.Combine(_dir, "vault.db")))
        {
            var rows = db.GetCollection<SnmpCredentialVault.Entry>("snmp_credentials");
            var row = rows.FindById(Scope().Key);
            row.ProtectedPayload = new byte[] { 1, 2, 3 };
            rows.Update(row);
        }
        int calls = 0;
        var manager = new ActiveSensorManager(() => _now, _ => Adapter,
            snmpProbe: (_, _, _, _) => { calls++; return Task.FromResult(new ActiveSensorRun("Observed", true, null)); });
        manager.AddAuthorized(p, Store(), grant.GrantId);
        Assert.True(await manager.RunDueAsync(default));
        Assert.Equal(0, calls);
        Assert.True(Assert.Single(manager.Snapshot()).ScopeBlocked);
    }

    [Fact]
    public async Task GenericInjectionCannotEnableStandaloneSnmpTransport()
    {
        var p = Profile();
        var grant = Grant(p);
        int resolutions = 0, probes = 0;
        var manager = new ActiveSensorManager(() => _now, _ => { resolutions++; return Adapter; },
            probe: (_, _, _) => { probes++; return Task.FromResult(new ActiveSensorRun("Unexpected", true, null)); });
        manager.AddAuthorized(p, Store(), grant.GrantId);
        await Assert.ThrowsAsync<InvalidOperationException>(() => manager.RunDueAsync(default));
        Assert.Equal(0, resolutions); Assert.Equal(0, probes);
        Assert.Null(Assert.Single(manager.Snapshot()).LastRunUtc);
    }

    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }
}
