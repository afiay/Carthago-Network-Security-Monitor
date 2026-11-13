// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services;
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

public sealed class ScheduledGatewayTests : IDisposable
{
    private static readonly Guid AdapterId = Guid.Parse("02702701-1234-4321-9999-000000000001");
    private static readonly LocalLanInterface Adapter = new("lab", IPAddress.Parse("192.168.50.10"), IPAddress.Parse("255.255.255.0"));
    private static readonly IPAddress Target = IPAddress.Parse("192.168.50.1");
    private static readonly DateTimeOffset Initial = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "carthago-gateway-schedule-" + Guid.NewGuid().ToString("N"));
    private DateTimeOffset _now = Initial;
    private ActiveSensorProfileStore Store() => new(Path.Combine(_dir, "profiles.db"), () => _now);
    private static ActiveSensorProfile Profile() => ActiveSensorProfile.Create(AdapterId, Adapter, Target,
        ActiveSensorKind.Gateway, "", 0, TimeSpan.FromMinutes(5), true);
    private ActiveExecutionGrant Grant(ActiveSensorProfile p)
    {
        Assert.True(Store().Save(p));
        return Assert.IsType<ActiveExecutionGrant>(Store().Grant(p, TimeSpan.FromHours(1)));
    }

    [Fact]
    public void ConfigurationIsCanonicalAndRequiresDurableGrant()
    {
        var p = ActiveSensorProfile.Create(AdapterId, Adapter, Target, ActiveSensorKind.Gateway,
            "ignored.example", 443, TimeSpan.FromMinutes(5), true);
        Assert.Equal("", p.HostName);
        Assert.Equal(0, p.Port);
        Assert.True(Store().Save(p));
        var saved = Assert.Single(Store().Read().Rows);
        Assert.Equal("Gateway", saved.Sensor);
        Assert.Equal("", saved.HostName);
        using (var db = new LiteDB.LiteDatabase(Path.Combine(_dir, "profiles.db")))
        {
            var row = db.GetCollection("saved_active_profiles").FindById(saved.Id);
            Assert.NotNull(row);
            Assert.True(row["HostName"].IsString);
            Assert.Equal("", row["HostName"].AsString);
        }
        Assert.Throws<InvalidOperationException>(() => new ActiveSensorManager().Add(p));
        Assert.Null(Store().ReadValidGrant(p));
    }

    [Fact]
    public async Task ChangedConfiguredGatewayBlocksBeforeTransport()
    {
        var p = Profile(); var grant = Grant(p);
        int calls = 0;
        var manager = new ActiveSensorManager(() => _now, _ => Adapter,
            gatewayCurrent: _ => false,
            gatewayProbe: (_, _, _, _) => { calls++; return Task.FromResult(new ActiveSensorRun("Observed", true, null)); });
        manager.AddAuthorized(p, Store(), grant.GrantId);
        Assert.True(await manager.RunDueAsync(default));
        Assert.Equal(0, calls);
        Assert.True(Assert.Single(manager.Snapshot()).ScopeBlocked);
        Assert.False(await manager.RunDueAsync(default));
    }

    [Fact]
    public async Task CaptureContentionDefersWithoutEvidenceOrFailureCount()
    {
        var p = Profile(); var grant = Grant(p);
        int calls = 0, writes = 0;
        var manager = new ActiveSensorManager(() => _now, _ => Adapter,
            save: _ => { writes++; return true; }, gatewayCurrent: _ => true,
            gatewayProbe: (_, _, _, _) =>
            {
                calls++;
                if (calls == 1) throw new CaptureReservationUnavailableException(new InvalidOperationException("busy"));
                return Task.FromResult(new ActiveSensorRun("Observed", true, new ActiveEvidenceRow()));
            });
        manager.AddAuthorized(p, Store(), grant.GrantId);
        Assert.True(await manager.RunDueAsync(default));
        var state = Assert.Single(manager.Snapshot());
        Assert.Equal("Capture unavailable — deferred", state.LastOutcome);
        Assert.Equal(0, state.ConsecutiveFailures);
        Assert.False(state.ScopeBlocked);
        Assert.Equal(0, writes);
        Assert.Equal(Initial.AddMinutes(5), state.NextDueUtc);
        Assert.False(await manager.RunDueAsync(default));
        _now = state.NextDueUtc;
        Assert.True(await manager.RunDueAsync(default));
        Assert.Equal(2, calls);
        Assert.Equal(1, writes);
    }

    [Fact]
    public async Task ScopeChangeDuringProbeSuppressesPersistence()
    {
        var p = Profile(); var grant = Grant(p);
        bool current = true; int writes = 0;
        var manager = new ActiveSensorManager(() => _now, _ => Adapter,
            save: _ => { writes++; return true; }, gatewayCurrent: _ => current,
            gatewayProbe: (_, _, authorized, _) =>
            {
                Assert.True(authorized());
                current = false;
                Assert.False(authorized());
                return Task.FromResult(new ActiveSensorRun("Observed", true, new ActiveEvidenceRow()));
            });
        manager.AddAuthorized(p, Store(), grant.GrantId);
        Assert.True(await manager.RunDueAsync(default));
        Assert.Equal(0, writes);
        Assert.True(Assert.Single(manager.Snapshot()).ScopeBlocked);
    }

    [Fact]
    public async Task RevocationDuringProbeMakesAuthorizationPredicateFalse()
    {
        var p = Profile(); var grant = Grant(p);
        int writes = 0;
        var manager = new ActiveSensorManager(() => _now, _ => Adapter,
            save: _ => { writes++; return true; }, gatewayCurrent: _ => true,
            gatewayProbe: (_, _, authorized, _) =>
            {
                Assert.True(authorized());
                Assert.True(Store().Revoke(grant.Id));
                Assert.False(authorized());
                throw new GatewayScopeChangedException();
            });
        manager.AddAuthorized(p, Store(), grant.GrantId);
        Assert.True(await manager.RunDueAsync(default));
        Assert.Equal(0, writes);
        Assert.True(Assert.Single(manager.Snapshot()).ScopeBlocked);
    }

    [Fact]
    public async Task CompletedNoReplyIsDistinctFromContention()
    {
        var p = Profile(); var grant = Grant(p);
        int writes = 0;
        var manager = new ActiveSensorManager(() => _now, _ => Adapter,
            save: row => { Assert.Equal("NoReply", row.Status); writes++; return true; },
            gatewayCurrent: _ => true, gatewayProbe: (_, _, _, _) =>
            {
                var row = ActiveEvidenceProjection.From(AdapterId, GatewayIntegritySensor.Evaluate(Adapter.Address,
                    Target, Array.Empty<string>(), null, null));
                return Task.FromResult(new ActiveSensorRun("NoReply", false, row));
            });
        manager.AddAuthorized(p, Store(), grant.GrantId);
        Assert.True(await manager.RunDueAsync(default));
        var state = Assert.Single(manager.Snapshot());
        Assert.Equal(1, writes);
        Assert.Equal("NoReply", state.LastOutcome);
        Assert.Equal(1, state.ConsecutiveFailures);
        Assert.Equal(Initial.AddMinutes(10), state.NextDueUtc);
    }

    [Fact]
    public async Task HeadlessRejectsNonGatewayBeforeCreatingScheduler()
    {
        var p = Profile(); var grant = Grant(p);
        using var output = new StringWriter();
        using var error = new StringWriter();
        int managers = 0;
        var result = await ActiveSensorWorker.ExecuteCoreAsync(new[] { "run", "--profile", grant.Id },
            output, error, default, Store(), _ => new[] { Adapter },
            () => { managers++; return new ActiveSensorManager(); }, () => _now, _ => false);
        Assert.Equal(3, result);
        Assert.Equal(0, managers);
        Assert.Contains("no longer the configured gateway", error.ToString());
    }

    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }
}
