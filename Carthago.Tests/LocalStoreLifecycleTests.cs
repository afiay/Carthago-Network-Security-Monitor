// SPDX-License-Identifier: MIT
// GA storage lifecycle — SOURCE CANDIDATE — UNVERIFIED (owner Windows tests pending).
using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Analytics.Models;
using Carthago.Analytics.Services;
using Xunit;

namespace Carthago.Tests;

public sealed class LocalStoreLifecycleTests
{
    private static string UniquePath()
        => Path.Combine(Path.GetTempPath(), "carthago-lifecycle-" + Guid.NewGuid().ToString("N") + ".db");

    [Fact]
    public void Dispose_Is_Idempotent_And_PostClose_Writes_Report_Failure()
    {
        var path = UniquePath();
        var store = new LocalStore(path);
        Assert.True(store.SaveIncident(new Incident { Id = "before-close", Title = "Persisted" }));

        store.Dispose();
        store.Dispose();

        Assert.False(store.SaveIncident(new Incident { Id = "after-close", Title = "Rejected" }));
        Assert.False(store.SaveBaselineSnapshots(new[]
        {
            new BaselineSnapshot { HostId = "10.0.0.9" }
        }));
        Assert.Empty(store.LoadIncidents());
        Assert.Empty(store.LoadAnomalies());
        Assert.Empty(store.LoadBaselineSnapshots());

        using var reopened = new LocalStore(path);
        Assert.Equal("before-close", Assert.Single(reopened.LoadIncidents()).Id);
    }

    [Fact]
    public async Task Concurrent_Incident_Writes_And_Dispose_Preserve_Every_Acknowledged_Write()
    {
        var path = UniquePath();
        var store = new LocalStore(path);
        Assert.True(store.SaveIncident(new Incident { Id = "seed", Title = "Acknowledged before racing" }));
        using var release = new ManualResetEventSlim(false);
        var writers = Enumerable.Range(0, 32).Select(i => Task.Run(() =>
        {
            release.Wait();
            var id = "race-" + i;
            return (Id: id, Saved: store.SaveIncident(new Incident { Id = id, Title = "Race test" }));
        })).ToArray();
        var closing = Task.Run(() =>
        {
            release.Wait();
            store.Dispose();
        });

        release.Set();
        await Task.WhenAll(writers);
        await closing;

        var accepted = writers.Where(task => task.Result.Saved)
            .Select(task => task.Result.Id)
            .ToHashSet(StringComparer.Ordinal);
        accepted.Add("seed");
        Assert.False(store.SaveIncident(new Incident { Id = "late", Title = "Must fail" }));

        using var reopened = new LocalStore(path);
        var persisted = reopened.LoadIncidents(100)
            .Select(incident => incident.Id)
            .ToHashSet(StringComparer.Ordinal);
        Assert.True(accepted.SetEquals(persisted),
            "Every acknowledged write must survive a concurrent Dispose without unexpected records.");
    }

    [Fact]
    public async Task Concurrent_Baseline_Writes_And_Dispose_Preserve_Every_Acknowledged_Host()
    {
        var path = UniquePath();
        var store = new LocalStore(path);
        Assert.True(store.SaveBaselineSnapshots(new[]
        {
            new BaselineSnapshot { HostId = "seed", ObservationWindows = 1 }
        }));
        using var release = new ManualResetEventSlim(false);
        var writers = Enumerable.Range(0, 16).Select(i => Task.Run(() =>
        {
            release.Wait();
            var host = "host-" + i;
            var saved = store.SaveBaselineSnapshots(new[]
            {
                new BaselineSnapshot { HostId = host, ObservationWindows = 1 }
            });
            return (Host: host, Saved: saved);
        })).ToArray();
        var closing = Task.Run(() =>
        {
            release.Wait();
            store.Dispose();
        });

        release.Set();
        await Task.WhenAll(writers);
        await closing;

        var accepted = writers.Where(task => task.Result.Saved)
            .Select(task => task.Result.Host)
            .ToHashSet(StringComparer.Ordinal);
        accepted.Add("seed");

        using var reopened = new LocalStore(path);
        var persisted = reopened.LoadBaselineSnapshots()
            .Select(snapshot => snapshot.HostId)
            .ToHashSet(StringComparer.Ordinal);
        Assert.True(accepted.SetEquals(persisted),
            "Successful baseline writes must remain readable after concurrent disposal.");
    }
}
