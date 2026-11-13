// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace Carthago.Services.Sensors;

internal sealed record ActiveServiceHealthSnapshot(int SchemaVersion, Guid SessionId, int ProcessId,
    DateTimeOffset ProcessStartedUtc, DateTimeOffset SampleUtc, bool SchedulerOwned,
    int Profiles, int BlockedProfiles, int PendingProfiles, int ProfilesWithFailures, int ResponsiveProfiles,
    long CompletedProbes, long ResponsiveProbes, long DeferredChecks, long StorageFailures,
    DateTimeOffset? LastResponsiveUtc, DateTimeOffset EarliestGrantExpiryUtc, DateTimeOffset LatestGrantExpiryUtc,
    string Assessment);

internal sealed class ActiveServiceHealthPublisher
{
    internal const string FileName = "health.json";
    private readonly string _root;
    private readonly Guid _session;
    private readonly int _pid;
    private readonly DateTimeOffset _started;
    private readonly Func<DateTimeOffset> _clock;
    private DateTimeOffset? _last;
    internal ActiveServiceHealthPublisher(string root, Guid session, int pid, DateTimeOffset started,
        Func<DateTimeOffset>? clock = null)
    { _root = root; _session = session; _pid = pid; _started = started; _clock = clock ?? (() => DateTimeOffset.UtcNow); }

    internal static ActiveServiceHealthSnapshot Build(Guid session, int pid, DateTimeOffset started,
        DateTimeOffset now, bool owned, ActiveSensorScheduleState[] states, DateTimeOffset earliest, DateTimeOffset latest)
    {
        int blocked = states.Count(s => s.ScopeBlocked), pending = states.Count(s => s.LastRunUtc is null);
        int failures = states.Count(s => s.ConsecutiveFailures > 0);
        int responsiveProfiles = states.Count(s => s.ResponsiveProbes > 0);
        long completed = states.Sum(s => s.CompletedProbes), responsive = states.Sum(s => s.ResponsiveProbes),
            deferred = states.Sum(s => s.DeferredChecks), storage = states.Sum(s => s.StorageFailures);
        string assessment = !owned || states.Length == 0 || blocked == states.Length || now >= latest ? "Unavailable" :
            storage > 0 || blocked > 0 || failures > 0 || states.Any(s => s.LastOutcome == "Capture unavailable — deferred") ||
            now >= earliest ? "Degraded" : pending > 0 || responsiveProfiles != states.Length ? "Pending" : "ResponsiveObserved";
        return new(2, session, pid, started, now, owned, states.Length, blocked, pending, failures, responsiveProfiles,
            completed, responsive, deferred, storage, states.Select(s => s.LastResponsiveUtc).DefaultIfEmpty(null).Max(), earliest, latest, assessment);
    }

    internal void Sample(ActiveSensorManager manager, DateTimeOffset earliest, DateTimeOffset latest)
    {
        var now = _clock();
        if (_last.HasValue && now >= _last.Value && now - _last.Value < TimeSpan.FromSeconds(5)) return;
        var snapshot = Build(_session, _pid, _started, now, manager.HasReservation, manager.Snapshot().ToArray(), earliest, latest);
        Write(_root, snapshot);
        _last = now;
    }

    internal static void Write(string root, ActiveServiceHealthSnapshot snapshot)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(snapshot, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        string path = Path.Combine(root, FileName);
        string temp = Path.Combine(root, "health-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { stream.Write(bytes); stream.Flush(true); }
            File.Move(temp, path, overwrite: true);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
}
