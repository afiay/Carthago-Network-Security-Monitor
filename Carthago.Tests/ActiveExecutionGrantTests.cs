// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Carthago.Services;
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

public sealed class ActiveExecutionGrantTests : IDisposable
{
    private static readonly Guid AdapterId = Guid.Parse("02702701-1234-4321-9999-000000000001");
    private static readonly LocalLanInterface Adapter = new("lab", IPAddress.Parse("192.168.50.10"), IPAddress.Parse("255.255.255.0"));
    private static readonly IPAddress Target = IPAddress.Parse("192.168.50.11");
    private static readonly DateTimeOffset Initial = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "carthago-grant-" + Guid.NewGuid().ToString("N"));
    private DateTimeOffset _now = Initial;
    private ActiveSensorProfileStore Store() => new(Path.Combine(_dir, "profiles.db"), () => _now);
    private static ActiveSensorProfile Profile(int minutes = 5, bool history = true) =>
        ActiveSensorProfile.Create(AdapterId, Adapter, Target, ActiveSensorKind.Dns, "lab.example", 53,
            TimeSpan.FromMinutes(minutes), history);

    [Fact]
    public void SavedConfigurationAloneCannotAuthorizeAndExpiryIsExclusive()
    {
        var profile = Profile();
        Assert.True(Store().Save(profile));
        Assert.Null(Store().ReadValidGrant(profile));
        var grant = Assert.IsType<ActiveExecutionGrant>(Store().Grant(profile, TimeSpan.FromHours(24)));
        Assert.True(Store().IsAuthorized(profile, grant.GrantId));
        _now = Initial.AddHours(24).AddTicks(-1);
        Assert.True(Store().IsAuthorized(profile, grant.GrantId));
        _now = Initial.AddHours(24);
        Assert.False(Store().IsAuthorized(profile, grant.GrantId));
        _now = Initial.AddTicks(-1);
        Assert.False(Store().IsAuthorized(profile, grant.GrantId));
    }

    [Fact]
    public void RevocationAndReissueNeverReactivateOldGrant()
    {
        var profile = Profile();
        Assert.True(Store().Save(profile));
        var original = Assert.IsType<ActiveExecutionGrant>(Store().Grant(profile, TimeSpan.FromHours(1)));
        Assert.True(Store().Revoke(original.Id));
        Assert.False(Store().Revoke(original.Id));
        Assert.False(Store().IsAuthorized(profile, original.GrantId));
        var replacement = Assert.IsType<ActiveExecutionGrant>(Store().Grant(profile, TimeSpan.FromHours(1)));
        Assert.NotEqual(original.GrantId, replacement.GrantId);
        Assert.True(Store().IsAuthorized(profile, replacement.GrantId));
        Assert.False(Store().IsAuthorized(profile, original.GrantId));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ExecutionParameterEditInvalidatesGrantEvenWhenChangedBack(bool interval)
    {
        var original = Profile();
        Assert.True(Store().Save(original));
        var grant = Assert.IsType<ActiveExecutionGrant>(Store().Grant(original, TimeSpan.FromHours(1)));
        Assert.True(Store().Save(Profile(interval ? 10 : 5, interval)));
        Assert.False(Store().IsAuthorized(original, grant.GrantId));
        Assert.True(Store().Save(original));
        Assert.Null(Store().ReadValidGrant(original));
    }

    [Fact]
    public void DeletionAndRecreationDoNotRestorePermission()
    {
        var profile = Profile();
        Assert.True(Store().Save(profile));
        var grant = Assert.IsType<ActiveExecutionGrant>(Store().Grant(profile, TimeSpan.FromHours(1)));
        Assert.True(Store().Delete(grant.Id));
        Assert.False(Store().IsAuthorized(profile, grant.GrantId));
        Assert.True(Store().Save(profile));
        Assert.Null(Store().ReadValidGrant(profile));
    }

    [Fact]
    public void GrantRequiresExactCurrentSavedConfiguration()
    {
        var profile = Profile();
        Assert.Null(Store().Grant(profile, TimeSpan.FromHours(1)));
        Assert.True(Store().Save(profile));
        Assert.Null(Store().Grant(Profile(10), TimeSpan.FromHours(1)));
        Assert.Null(Store().Grant(Profile(history: false), TimeSpan.FromHours(1)));
        var grant = Assert.IsType<ActiveExecutionGrant>(Store().Grant(profile, TimeSpan.FromHours(1)));
        Assert.True(Store().Save(profile)); // unchanged save retains authorization
        Assert.True(Store().IsAuthorized(profile, grant.GrantId));
    }

    [Fact]
    public async Task RevokedLoadedGrantBlocksBeforeTransportAndReplacementDoesNotUnblock()
    {
        var profile = Profile();
        var store = Store();
        Assert.True(store.Save(profile));
        var grant = Assert.IsType<ActiveExecutionGrant>(store.Grant(profile, TimeSpan.FromHours(1)));
        int calls = 0;
        var manager = new ActiveSensorManager(() => _now, _ => Adapter,
            (_, _, _) => { calls++; return Task.FromResult(new ActiveSensorRun("OK", true, null)); });
        manager.AddAuthorized(profile, store, grant.GrantId);
        Assert.True(store.Revoke(grant.Id));
        Assert.NotNull(store.Grant(profile, TimeSpan.FromHours(1)));
        Assert.True(await manager.RunDueAsync(default));
        Assert.Equal(0, calls);
        Assert.True(Assert.Single(manager.Snapshot()).ScopeBlocked);
        Assert.False(await manager.RunDueAsync(default));
    }

    [Fact]
    public async Task RevocationDuringProbeSuppressesEvidencePersistence()
    {
        var profile = Profile();
        var store = Store();
        Assert.True(store.Save(profile));
        var grant = Assert.IsType<ActiveExecutionGrant>(store.Grant(profile, TimeSpan.FromHours(1)));
        int writes = 0;
        var manager = new ActiveSensorManager(() => _now, _ => Adapter,
            (_, _, _) =>
            {
                Assert.True(store.Revoke(grant.Id));
                return Task.FromResult(new ActiveSensorRun("OK", true, new ActiveEvidenceRow()));
            }, _ => { writes++; return true; });
        manager.AddAuthorized(profile, store, grant.GrantId);
        Assert.True(await manager.RunDueAsync(default));
        var state = Assert.Single(manager.Snapshot());
        Assert.Equal(0, writes);
        Assert.True(state.ScopeBlocked);
        Assert.Equal("Not saved", state.HistoryStatus);
        Assert.Contains("Authorization ended", state.LastOutcome);
    }

    [Fact]
    public void InvalidDurationAndMissingGrantCannotLoadAuthorizedProfile()
    {
        var profile = Profile();
        var store = Store();
        Assert.True(store.Save(profile));
        Assert.Null(store.Grant(profile, TimeSpan.Zero));
        Assert.Null(store.Grant(profile, TimeSpan.FromHours(25)));
        Assert.Null(store.Grant(profile, TimeSpan.FromMinutes(-1)));
        var manager = new ActiveSensorManager();
        Assert.Throws<InvalidOperationException>(() => manager.AddAuthorized(profile, store, Guid.NewGuid()));
        Assert.Empty(manager.Snapshot());
    }

    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }
}
