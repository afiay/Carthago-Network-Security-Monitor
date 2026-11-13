// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services;
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

public sealed class ActiveSensorLifecycleStressTests : IDisposable
{
    private static readonly Guid AdapterId = Guid.Parse("02702701-1234-4321-9999-000000000001");
    private static readonly IPAddress Source = IPAddress.Parse("192.168.50.10");
    private static readonly IPAddress Target = IPAddress.Parse("192.168.50.11");
    private static readonly LocalLanInterface Adapter = new("lab", Source, IPAddress.Parse("255.255.255.0"));
    private static readonly DateTimeOffset Initial = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "carthago-stress-" + Guid.NewGuid().ToString("N"));
    private string DbPath => Path.Combine(_dir, "active.db");
    private DateTimeOffset _now = Initial;
    private ActiveEvidenceStore Store(int capacity = 5000, Action? beforeCommit = null) =>
        new(DbPath, capacity, () => _now, beforeCommit);
    private static ActiveEvidenceRow Row(DateTimeOffset time, string address = "192.0.2.10", string name = "lab.example") =>
        ActiveEvidenceProjection.From(AdapterId, new DnsIntegrityObservation(Source, Target, name,
            DnsIntegrityStatus.AnswersObserved, new[] { address }, 0, time, TimeSpan.Zero, null));
    private static ActiveSensorProfile Profile(string name = "lab.example") =>
        ActiveSensorProfile.Create(AdapterId, Adapter, Target, ActiveSensorKind.Dns, name, 53,
            TimeSpan.FromMinutes(5), true);

    [Fact]
    public async Task ConcurrentIndependentScopesRemainDurableAcrossReopen()
    {
        var rows = Enumerable.Range(0, 24).Select(i => Row(Initial, name: $"host{i}.example")).ToArray();
        var results = await Task.WhenAll(rows.Select(row => Task.Run(() => Store().Save(row))));
        Assert.All(results, ok => Assert.True(ok));
        var read = Store().Read();
        Assert.Null(read.Error);
        Assert.Equal(24, read.Rows.Count);
        Assert.Equal(rows.Select(r => r.Id).OrderBy(x => x), read.Rows.Select(r => r.Id).OrderBy(x => x));
        Assert.Empty(Store().ReadFindings().Rows);
    }

    [Fact]
    public async Task ConcurrentDuplicateIdHasExactlyOneWinner()
    {
        var row = Row(Initial);
        var results = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => Task.Run(() => Store().Save(row))));
        Assert.Equal(1, results.Count(x => x));
        Assert.Equal(row.Id, Assert.Single(Store().Read().Rows).Id);
    }

    [Fact]
    public void FailureAfterFindingInsertRollsBackBothWritesAndAllowsRetry()
    {
        var baseline = Row(Initial);
        Assert.True(Store().Save(baseline));
        Assert.True(Store().Approve(baseline.Id));
        _now = Initial.AddMinutes(5);
        Assert.True(Store().Save(Row(_now, "192.0.2.20")));
        _now = Initial.AddMinutes(10);
        var confirming = Row(_now, "192.0.2.20");
        int invoked = 0;
        Assert.False(Store(beforeCommit: () => { invoked++; throw new IOException("Injected pre-commit failure"); }).Save(confirming));
        Assert.Equal(1, invoked);
        Assert.Equal(2, Store().Read().Rows.Count);
        Assert.Empty(Store().ReadFindings().Rows);
        Assert.True(Store().Save(confirming));
        Assert.Equal(3, Store().Read().Rows.Count);
        var finding = Assert.Single(Store().ReadFindings().Rows);
        Assert.Equal("ASD003", finding.RuleId);
        Assert.Equal(confirming.Id, finding.ConfirmingObservationId);
    }

    [Fact]
    public void RetentionPressureEvictsBaselineAndPreventsQualification()
    {
        var baseline = Row(Initial);
        Assert.True(Store(2).Save(baseline));
        Assert.True(Store(2).Approve(baseline.Id));
        _now = Initial.AddMinutes(5);
        Assert.True(Store(2).Save(Row(_now, "192.0.2.20")));
        _now = Initial.AddMinutes(10);
        var current = Row(_now, "192.0.2.20");
        Assert.True(Store(2).Save(current));
        Assert.Equal(2, Store(2).Read().Rows.Count);
        Assert.Equal("NoApprovedBaseline", Store(2).CompareApproved(current.Id).Status);
        Assert.Empty(Store(2).ReadFindings().Rows);
    }

    [Fact]
    public void CorruptDatabaseDoesNotReportSuccessfulSaveOrReplaceFile()
    {
        Directory.CreateDirectory(_dir);
        // A full page of non-LiteDB bytes rather than an empty database.
        var corrupt = Enumerable.Repeat((byte)0xA5, 8192).ToArray();
        File.WriteAllBytes(DbPath, corrupt);
        Assert.False(Store().Save(Row(Initial)));
        Assert.NotNull(Store().Read().Error);
        Assert.Equal(corrupt, File.ReadAllBytes(DbPath));
    }

    [Fact]
    public async Task CancellationDuringScopeResolutionNeverStartsProbe()
    {
        using var cts = new CancellationTokenSource();
        int probes = 0;
        var manager = new ActiveSensorManager(() => Initial, _ => { cts.Cancel(); return Adapter; },
            (_, _, _) => { probes++; return Task.FromResult(new ActiveSensorRun("OK", true, null)); });
        manager.Add(Profile());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => manager.RunDueAsync(cts.Token));
        Assert.Equal(0, probes);
        var state = Assert.Single(manager.Snapshot());
        Assert.False(state.Running);
        Assert.Equal("Cancelled", state.LastOutcome);
    }

    [Fact]
    public async Task StopDuringCommitWaitsForWriteAndPreventsNextProbe()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var release = new ManualResetEventSlim(false);
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int probes = 0;
        var manager = new ActiveSensorManager(() => Initial, _ => Adapter,
            (_, _, _) => { Interlocked.Increment(ref probes); return Task.FromResult(new ActiveSensorRun("OK", true, Row(Initial))); },
            row => Store(beforeCommit: () =>
            {
                entered.TrySetResult(true);
                if (!release.Wait(TimeSpan.FromSeconds(10))) throw new TimeoutException("Test release timed out");
            }).Save(row));
        manager.Add(Profile());
        manager.Add(Profile("other.example"));
        var running = Task.Run(() => manager.RunAsync(cts.Token));
        try
        {
            await entered.Task.WaitAsync(cts.Token);
            cts.Cancel();
            Assert.False(running.IsCompleted);
            Assert.False(await manager.RunDueAsync(CancellationToken.None));
        }
        finally { release.Set(); }
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.Equal(1, probes);
        Assert.All(manager.Snapshot(), s => Assert.False(s.Running));
        Assert.Single(manager.Snapshot().Where(s => s.HistoryStatus == "Saved"));
        Assert.Single(Store().Read().Rows);
    }

    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }
}
