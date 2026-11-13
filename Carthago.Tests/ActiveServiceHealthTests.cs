// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Services;
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

public sealed class ActiveServiceHealthTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);
    private static ActiveSensorProfile Profile() => ActiveSensorProfile.Create(Guid.NewGuid(),
        new LocalLanInterface("lab", IPAddress.Parse("192.168.50.10"), IPAddress.Parse("255.255.255.0")),
        IPAddress.Parse("192.168.50.11"), ActiveSensorKind.Dns, "lab.example", 53, TimeSpan.FromMinutes(5), true);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "carthago-health-" + Guid.NewGuid().ToString("N"));
    private static ActiveServiceHealthSnapshot Build(params ActiveSensorScheduleState[] states) =>
        ActiveServiceHealthPublisher.Build(Guid.NewGuid(), 123, Now.AddMinutes(-1), Now, true, states, Now.AddHours(1), Now.AddHours(2));

    [Fact]
    public async Task ResponsiveAndStorageFailureAreSeparateCounters()
    {
        var p = Profile();
        var manager = new ActiveSensorManager(() => Now, _ => p.Adapter,
            (_, _, _) => Task.FromResult(new ActiveSensorRun("AnswersObserved", true, new ActiveEvidenceRow())), _ => false);
        manager.Add(p);
        Assert.True(await manager.RunDueAsync(default));
        var snapshot = Build(manager.Snapshot().ToArray());
        Assert.Equal(1, snapshot.CompletedProbes);
        Assert.Equal(1, snapshot.ResponsiveProbes);
        Assert.Equal(1, snapshot.StorageFailures);
        Assert.Equal(Now, snapshot.LastResponsiveUtc);
        Assert.Equal("Degraded", snapshot.Assessment);
    }

    [Fact]
    public void PendingBlockedAndDeferredAreDistinct()
    {
        var state = new ActiveSensorScheduleState(Profile(), Now, null, "Not run", 0, false, false, "Not requested");
        Assert.Equal("Pending", Build(state).Assessment);
        Assert.Equal("Unavailable", Build(state with { ScopeBlocked = true }).Assessment);
        var deferred = Build(state with { LastRunUtc = Now, LastOutcome = "Capture unavailable — deferred", DeferredChecks = 1 });
        Assert.Equal("Degraded", deferred.Assessment);
        Assert.Equal(0, deferred.CompletedProbes);
        Assert.Equal(1, deferred.DeferredChecks);
    }

    [Fact]
    public void ResponsiveDoesNotClaimSecurityAccuracyAndExpiredIsUnavailable()
    {
        var state = new ActiveSensorScheduleState(Profile(), Now, Now, "CertificateRejected", 0, false, false, "Saved")
            { CompletedProbes = 1, ResponsiveProbes = 1, LastResponsiveUtc = Now };
        Assert.Equal("ResponsiveObserved", Build(state).Assessment);
        var expired = ActiveServiceHealthPublisher.Build(Guid.NewGuid(), 1, Now.AddMinutes(-1), Now, true,
            new[] { state }, Now.AddMinutes(-1), Now);
        Assert.Equal("Unavailable", expired.Assessment);
        Assert.Equal("Unavailable", Build().Assessment);
    }

    [Fact]
    public void SnapshotIsAtomicAndExcludesProfileAndCredentialData()
    {
        Directory.CreateDirectory(_dir);
        var state = new ActiveSensorScheduleState(Profile(), Now, Now, "AnswersObserved", 0, false, false, "Saved");
        var sample = Build(state);
        ActiveServiceHealthPublisher.Write(_dir, sample);
        ActiveServiceHealthPublisher.Write(_dir, sample with { CompletedProbes = 2 });
        var raw = File.ReadAllText(Path.Combine(_dir, ActiveServiceHealthPublisher.FileName));
        using var json = JsonDocument.Parse(raw);
        Assert.Equal(2, json.RootElement.GetProperty("completedProbes").GetInt64());
        Assert.DoesNotContain("lab.example", raw);
        Assert.DoesNotContain("192.168", raw);
        Assert.Single(Directory.GetFiles(_dir));
    }
    [Fact]
    public void AggregateResponsesCannotSubstituteForDistinctResponsiveProfiles()
    {
        var a = new ActiveSensorScheduleState(Profile(), Now, Now, "AnswersObserved", 0, false, false, "Saved")
            { CompletedProbes = 3, ResponsiveProbes = 3, LastResponsiveUtc = Now };
        var b = new ActiveSensorScheduleState(Profile(), Now, Now, "Not responsive", 0, false, false, "Not requested");
        var snapshot = Build(a, b);
        Assert.Equal(2, snapshot.SchemaVersion);
        Assert.Equal(3, snapshot.ResponsiveProbes);
        Assert.Equal(1, snapshot.ResponsiveProfiles);
        Assert.Equal("Pending", snapshot.Assessment);
        var full = Build(a, b with { CompletedProbes = 1, ResponsiveProbes = 1, LastResponsiveUtc = Now });
        Assert.Equal(2, full.ResponsiveProfiles);
        Assert.Equal("ResponsiveObserved", full.Assessment);
    }
    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }
}
