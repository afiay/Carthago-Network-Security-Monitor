// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services;
using Carthago.Services.Sensors;
using Carthago.Contracts;
using Xunit;

namespace Carthago.Tests;

public sealed class ActiveSensorWorkerTests : IDisposable
{
    private static readonly Guid AdapterId = Guid.Parse("02702701-1234-4321-9999-000000000001");
    private static readonly LocalLanInterface Adapter = new("lab", IPAddress.Parse("192.168.50.10"), IPAddress.Parse("255.255.255.0"));
    private static readonly IPAddress Target = IPAddress.Parse("192.168.50.11");
    private static readonly DateTimeOffset Initial = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "carthago-worker-" + Guid.NewGuid().ToString("N"));
    private DateTimeOffset _now = Initial;
    private ActiveSensorProfileStore Store() => new(Path.Combine(_dir, "profiles.db"), () => _now);
    private static ActiveSensorProfile Profile(string name = "lab.example") =>
        ActiveSensorProfile.Create(AdapterId, Adapter, Target, ActiveSensorKind.Dns, name, 53, TimeSpan.FromMinutes(5), false);
    private string Save(ActiveSensorProfile p, bool grant = true)
    {
        Assert.True(Store().Save(p));
        if (grant) Assert.NotNull(Store().Grant(p, TimeSpan.FromHours(1)));
        return SavedActiveSensorProfile.From(p).Id;
    }
    private Task<int> Execute(string[] args, StringWriter output, StringWriter error, CancellationToken token = default,
        Func<Guid, System.Collections.Generic.IReadOnlyList<LocalLanInterface>>? resolve = null,
        Func<ActiveSensorManager>? manager = null) =>
        ActiveSensorWorker.ExecuteCoreAsync(args, output, error, token, Store(),
            resolve ?? (_ => new[] { Adapter }), manager ?? (() => throw new InvalidOperationException("Unexpected manager")), () => _now);

    [Fact]
    public async Task StatusIsConfigurationOnlyAndDoesNotResolveOrExecute()
    {
        Save(Profile()); Save(Profile("other.example"), false);
        using var output = new StringWriter(); using var error = new StringWriter();
        Assert.Equal(0, await Execute(new[] { "status", "--json" }, output, error,
            resolve: _ => throw new InvalidOperationException("Unexpected resolution")));
        using var json = JsonDocument.Parse(output.ToString());
        var root = json.RootElement;
        Assert.False(root.GetProperty("liveScopeValidated").GetBoolean());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("schedulerRunning").ValueKind);
        var rows = root.GetProperty("profiles").EnumerateArray().ToArray();
        Assert.Equal(2, rows.Length);
        Assert.Contains(rows, r => r.GetProperty("authorization").GetString() == "Valid");
        Assert.Contains(rows, r => r.GetProperty("authorization").GetString() == "NoValidGrant");
    }

    [Fact]
    public async Task InvalidArgumentsAndDuplicateIdsRejectedWithoutStorage()
    {
        using var output = new StringWriter(); using var error = new StringWriter();
        string id = new('a', 64);
        Assert.Equal(2, await Execute(new[] { "run", "--profile", id, "--profile", id }, output, error));
        Assert.Equal(2, await Execute(new[] { "run", "--profile", "bad" }, output, error));
        Assert.Equal(2, await Execute(new[] { "status", "--unknown" }, output, error));
        Assert.False(Directory.Exists(_dir));
    }

    [Fact]
    public async Task MissingOrExpiredGrantDoesNotCreateManager()
    {
        string id = Save(Profile(), false);
        using var output = new StringWriter(); using var error = new StringWriter();
        Assert.Equal(3, await Execute(new[] { "run", "--profile", id }, output, error));
        Assert.Contains("no valid durable grant", error.ToString());
        Assert.NotNull(Store().Grant(Profile(), TimeSpan.FromHours(1)));
        _now = Initial.AddHours(1);
        Assert.Equal(3, await Execute(new[] { "run", "--profile", id }, output, error));
    }

    [Fact]
    public async Task ScopeMismatchAndAmbiguityRejectStartup()
    {
        string id = Save(Profile());
        using var output = new StringWriter(); using var error = new StringWriter();
        Assert.Equal(3, await Execute(new[] { "run", "--profile", id }, output, error, resolve: _ => Array.Empty<LocalLanInterface>()));
        Assert.Equal(3, await Execute(new[] { "run", "--profile", id }, output, error, resolve: _ => new[] { Adapter, Adapter }));
    }

    [Fact]
    public async Task SelectionIsAllOrNothing()
    {
        string good = Save(Profile());
        string bad = Save(Profile("other.example"), false);
        using var output = new StringWriter(); using var error = new StringWriter();
        int managers = 0;
        Assert.Equal(3, await Execute(new[] { "run", "--profile", good, "--profile", bad }, output, error,
            manager: () => { managers++; return new ActiveSensorManager(); }));
        Assert.Equal(0, managers);
    }

    [Fact]
    public async Task ExplicitRunHonorsCancellationAndReleasesReservation()
    {
        string id = Save(Profile());
        string name = @"Global\Carthago.Test.ActiveScheduler." + Guid.NewGuid().ToString("N");
        using var output = new StringWriter(); using var error = new StringWriter();
        using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        int calls = 0;
        var manager = new ActiveSensorManager(() => _now, _ => Adapter,
            (_, _, _) => { calls++; cancel.Cancel(); return Task.FromResult(new ActiveSensorRun("OK", true, null)); },
            acquireReservation: () => WindowsActiveSchedulerReservation.AcquireNamed(name));
        Assert.Equal(130, await Execute(new[] { "run", "--profile", id }, output, error, cancel.Token, manager: () => manager));
        Assert.Equal(1, calls);
        Assert.False(manager.HasReservation);
        using var next = WindowsActiveSchedulerReservation.AcquireNamed(name);
    }

    [Fact]
    public async Task RevocationAfterLoadingBlocksExecutionAndExits()
    {
        var p = Profile();
        string id = Save(p);
        string name = @"Global\Carthago.Test.ActiveScheduler." + Guid.NewGuid().ToString("N");
        using var output = new StringWriter(); using var error = new StringWriter();
        using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        int calls = 0;
        var manager = new ActiveSensorManager(() => _now, _ => Adapter,
            (_, _, _) => { calls++; return Task.FromResult(new ActiveSensorRun("OK", true, null)); },
            acquireReservation: () =>
            {
                Assert.True(Store().Revoke(id));
                return WindowsActiveSchedulerReservation.AcquireNamed(name);
            });
        Assert.Equal(3, await Execute(new[] { "run", "--profile", id }, output, error, cancel.Token, manager: () => manager));
        Assert.Equal(0, calls);
        Assert.False(manager.HasReservation);
        Assert.Contains("All selected profiles blocked", error.ToString());
    }

    [Fact]
    public async Task PinnedGrantRejectsReplacementBeforeManagerOrReadiness()
    {
        var p = Profile();
        var id = Save(p);
        var original = Assert.IsType<ActiveExecutionGrant>(Store().ReadValidGrant(p));
        var replacement = Assert.IsType<ActiveExecutionGrant>(Store().Grant(p, TimeSpan.FromHours(1)));
        Assert.NotEqual(original.GrantId, replacement.GrantId);
        using var output = new StringWriter();
        using var error = new StringWriter();
        int managers = 0, ready = 0;
        var result = await ActiveSensorWorker.ExecuteCoreAsync(new[] { "run", "--profile", id },
            output, error, default, Store(), _ => new[] { Adapter },
            () => { managers++; return new ActiveSensorManager(); }, () => _now,
            pinnedGrants: new System.Collections.Generic.Dictionary<string, Guid> { [id] = original.GrantId },
            ready: () => ready++);
        Assert.Equal(3, result);
        Assert.Equal(0, managers);
        Assert.Equal(0, ready);
        Assert.Contains("does not match the pinned grant", error.ToString());
    }

    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }
}
