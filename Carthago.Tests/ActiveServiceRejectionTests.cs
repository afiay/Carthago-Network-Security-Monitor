// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Net;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Services;
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

public sealed class ActiveServiceRejectionTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "carthago-rejection-" + Guid.NewGuid().ToString("N"));
    private static readonly Guid AdapterId = Guid.Parse("02702701-1234-4321-9999-000000000001");
    private static readonly LocalLanInterface Adapter = new("lab", IPAddress.Parse("192.168.50.10"), IPAddress.Parse("255.255.255.0"));
    private static readonly IPAddress Target = IPAddress.Parse("192.168.50.11");
    private ActiveSensorProfileStore Store() => new(Path.Combine(_dir, "profiles.db"));
    [Theory]
    [InlineData("missing", "NoValidGrant")]
    [InlineData("revoked", "NoValidGrant")]
    [InlineData("replaced", "PinnedGrantMismatch")]
    public async Task TypedRejectionBeforeManagerOrReadiness(string mode, string expected)
    {
        var profile = ActiveSensorProfile.Create(AdapterId, Adapter, Target, ActiveSensorKind.Dns, "lab.example", 53, TimeSpan.FromMinutes(5), true);
        var store = Store();
        Assert.True(store.Save(profile));
        var id = SavedActiveSensorProfile.From(profile).Id;
        Guid pinned = Guid.NewGuid();
        if (mode != "missing")
        {
            var grant = Assert.IsType<ActiveExecutionGrant>(store.Grant(profile, TimeSpan.FromHours(1)));
            pinned = grant.GrantId;
            if (mode == "revoked") Assert.True(store.Revoke(id));
            else Assert.NotNull(store.Grant(profile, TimeSpan.FromHours(1)));
        }
        int managers = 0, ready = 0, samples = 0;
        var reasons = new List<ActiveServiceRejectionReason>();
        using var output = new StringWriter(); using var error = new StringWriter();
        int result = await ActiveSensorWorker.ExecuteCoreAsync(new[] { "run", "--profile", id }, output, error, default,
            store, _ => new[] { Adapter }, () => { managers++; return new ActiveSensorManager(); },
            pinnedGrants: new Dictionary<string, Guid> { [id] = pinned }, ready: () => ready++,
            sample: (_, _, _) => samples++, startupRejected: reasons.Add);
        Assert.Equal(3, result);
        Assert.Equal(expected, Assert.Single(reasons).ToString());
        Assert.Equal(0, managers); Assert.Equal(0, ready); Assert.Equal(0, samples);
    }

    [Fact]
    public void RejectionRecordIsBoundedAllowlistedAndReplaced()
    {
        Directory.CreateDirectory(_dir);
        var started = DateTimeOffset.UtcNow.AddSeconds(-1);
        var publisher = new ActiveServiceStartupRejection(_dir, 123, started, new string('A', 64));
        publisher.Publish(ActiveServiceRejectionReason.NoValidGrant);
        string file = Path.Combine(_dir, ActiveServiceStartupRejection.FileName);
        using var first = JsonDocument.Parse(File.ReadAllBytes(file));
        publisher.Publish(ActiveServiceRejectionReason.SnmpCredentialUnavailable);
        using var second = JsonDocument.Parse(File.ReadAllBytes(file));
        var row = second.RootElement;
        Assert.NotEqual(first.RootElement.GetProperty("attemptId").GetGuid(), row.GetProperty("attemptId").GetGuid());
        Assert.Equal("SnmpCredentialUnavailable", row.GetProperty("reason").GetString());
        Assert.Equal(123, row.GetProperty("processId").GetInt32());
        Assert.Equal(new string('A', 64), row.GetProperty("configSha256").GetString());
        Assert.False(row.GetProperty("readinessPublished").GetBoolean());
        Assert.Equal(8, System.Linq.Enumerable.Count(row.EnumerateObject()));
        Assert.Single(Directory.GetFiles(_dir));
    }
    [Fact]
    public async Task CorruptSnmpCiphertextReportsTypedRejectionBeforeReadiness()
    {
        var vaultPath = Path.Combine(_dir, "credentials.db");
        var vault = new SnmpCredentialVault(vaultPath);
        var store = new ActiveSensorProfileStore(Path.Combine(_dir, "profiles.db"), vault: vault);
        var profile = ActiveSensorProfile.Create(AdapterId, Adapter, Target, ActiveSensorKind.Snmp, "", 161, TimeSpan.FromMinutes(5), true);
        var scope = SnmpCredentialScope.Create(AdapterId, Adapter, Target);
        Assert.True(store.Save(profile));
        var generation = vault.Save(scope, new SnmpCredential("lab-user", "authphrase", "privphrase"));
        var grant = Assert.IsType<ActiveExecutionGrant>(store.Grant(profile, TimeSpan.FromHours(1), generation));
        using (var db = new LiteDB.LiteDatabase(vaultPath))
        {
            var rows = db.GetCollection<SnmpCredentialVault.Entry>("snmp_credentials");
            var row = rows.FindById(scope.Key);
            row.ProtectedPayload = new byte[] { 1, 2, 3 };
            Assert.True(rows.Update(row));
        }
        var reasons = new List<ActiveServiceRejectionReason>();
        int managers = 0, ready = 0, samples = 0;
        using var output = new StringWriter(); using var error = new StringWriter();
        Assert.Equal(3, await ActiveSensorWorker.ExecuteCoreAsync(new[] { "run", "--profile", grant.Id },
            output, error, default, store, _ => new[] { Adapter },
            () => { managers++; return new ActiveSensorManager(); },
            pinnedGrants: new Dictionary<string, Guid> { [grant.Id] = grant.GrantId },
            ready: () => ready++, sample: (_, _, _) => samples++, startupRejected: reasons.Add));
        Assert.Equal(ActiveServiceRejectionReason.SnmpCredentialUnavailable, Assert.Single(reasons));
        Assert.Equal(0, managers); Assert.Equal(0, ready); Assert.Equal(0, samples);
    }

    [Fact]
    public void LoadedConfigurationHashIncludesExactParsedBytes()
    {
        Directory.CreateDirectory(_dir);
        var bytes = ActiveServiceProvisioning.BuildConfiguration("S-1-5-21-100-200-300-1001",
            new[] { new Carthago.Contracts.ActiveServiceSelection(new string('a', 64), Guid.NewGuid()) });
        string path = Path.Combine(_dir, "config.json");
        File.WriteAllBytes(path, bytes);
        var config = Carthago.Contracts.ActiveServiceConfiguration.Load(path, out string hash);
        Assert.Single(config.Profiles);
        Assert.Equal(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)), hash);
    }

    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }
}
