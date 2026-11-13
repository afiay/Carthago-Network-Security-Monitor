// SPDX-License-Identifier: MIT
using System.Text.Json;
using Carthago.Contracts;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PipelineHealthTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);
    private static PipelineTelemetry Good => new(true, Now.AddSeconds(-2), 0, 4096, 4, 4, 0, 0, 50, 0, 0, 0);
    private static ForegroundMonitorCounters Counters(PipelineTelemetry? p = null) => new(100, 99, 1, 0, p ?? Good);
    private static PipelineAssessment Assess(PipelineTelemetry p) => PipelineHealth.Assess(Counters(p), Now, Now, true);

    [Fact]
    public void HealthyDoesNotClaimJournalOrDetectionAccuracy()
    {
        var r = Assess(Good);
        Assert.Equal("healthy", r.State);
        Assert.Equal("not_exercised", r.Journal);
        Assert.Equal("not_assessed", r.DetectionValidation);
        Assert.Equal("persistence_observed", Assess(Good with { PersistedDetections = 3 }).Journal);
    }

    [Fact]
    public void IdleDoesNotAssumeCaptureFailure()
    {
        Assert.Equal("idle", Assess(Good with { LastPacketUtc = null, Evaluations = 0 }).State);
        Assert.Equal("idle", Assess(Good with { LastPacketUtc = Now.AddSeconds(-31) }).State);
        Assert.Equal("unknown", Assess(Good with { Evaluations = 0 }).State);
    }

    [Fact]
    public void FailedConditionsTakePrecedence()
    {
        Assert.Equal("failed", Assess(Good with { NativeStarted = false }).State);
        Assert.Equal("failed", Assess(Good with { WorkersAlive = 0 }).State);
        var r = Assess(Good with { JournalWriteFailures = 1, PersistedDetections = 20, LastPacketUtc = null });
        Assert.Equal("failed", r.State);
        Assert.Equal("write_failure_observed", r.Journal);
        Assert.Contains("journal_write_failure_observed", r.Reasons);
    }

    [Fact]
    public void DegradedConditionsAndQueueThreshold()
    {
        Assert.Equal("healthy", Assess(Good with { QueueDepth = 3276 }).State);
        Assert.Equal("degraded", Assess(Good with { QueueDepth = 3277 }).State);
        Assert.Equal("degraded", Assess(Good with { WorkersAlive = 3 }).State);
        Assert.Equal("degraded", Assess(Good with { WorkerFaults = 1 }).State);
        Assert.Equal("degraded", Assess(Good with { EnrichmentFallbacks = 1 }).State);
        Assert.Equal("degraded", Assess(Good with { RuleFailures = 1 }).State);
    }

    [Fact]
    public void ParseErrorRatioRequiresMinimumObservations()
    {
        Assert.Equal("healthy", PipelineHealth.Assess(new(19, 17, 2, 0, Good), Now, Now, true).State);
        Assert.Equal("degraded", PipelineHealth.Assess(new(20, 18, 2, 0, Good), Now, Now, true).State);
    }

    [Fact]
    public void MissingStaleFutureOrInconsistentSampleUnknown()
    {
        Assert.Equal("unknown", PipelineHealth.Assess(new(0, 0, 0, 0), Now, Now, true).State);
        Assert.Equal("unknown", PipelineHealth.Assess(Counters(), Now.AddSeconds(-121), Now, true).State);
        Assert.Equal("unknown", PipelineHealth.Assess(Counters(), Now.AddSeconds(1), Now, true).State);
        Assert.Equal("unknown", Assess(Good with { LastPacketUtc = Now.AddSeconds(1) }).State);
        Assert.Equal("unknown", Assess(Good with { QueueDepth = null }).State);
        Assert.Equal("unknown", PipelineHealth.Assess(Counters(), Now, Now, false).State);
    }

    [Fact]
    public void InvalidTelemetryRejected()
    {
        Assert.Throws<InvalidDataException>(() => Assess(Good with { QueueDepth = 4097 }));
        Assert.Throws<InvalidDataException>(() => Assess(Good with { WorkersAlive = 5 }));
        Assert.Throws<InvalidDataException>(() => Assess(Good with { JournalWriteFailures = -1 }));
    }

    [Fact]
    public void LegacyStatusOmitsPipelineButHealthReturnsIt()
    {
        var session = new MonitorControlSession(false, () => { });
        session.MarkStarted();
        session.Publish(Counters());
        var status = new MonitorControlRequest(4, Guid.NewGuid(), MonitorControlKind.Status);
        var health = new MonitorControlRequest(4, Guid.NewGuid(), MonitorControlKind.Health);
        var legacy = session.Query(status);
        Assert.Null(legacy.Counters!.Pipeline);
        Assert.DoesNotContain("pipeline", JsonSerializer.Serialize(legacy, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        var detailed = session.Query(health);
        MonitorControlProtocol.ValidateResponse(detailed, health);
        Assert.Equal(Good, detailed.Counters!.Pipeline);
        Assert.Throws<InvalidDataException>(() => MonitorControlProtocol.ValidateResponse(legacy with { Counters = Counters() }, status));
    }

    [Fact]
    public async Task ForegroundHealthCommandUsesDedicatedQuery()
    {
        var now = DateTimeOffset.UtcNow;
        var session = new MonitorControlSession(false, () => { });
        session.MarkStarted();
        session.Publish(Counters(Good with { LastPacketUtc = now.AddSeconds(-1) }));
        using var output = new StringWriter();
        using var error = new StringWriter();
        var code = await CliApplication.RunAsync(new[] { "engine", "health", "--json" }, output, error,
            monitorQuery: (q, _) =>
            {
                Assert.Equal(MonitorControlKind.Health, q.Kind);
                return Task.FromResult(session.Query(q));
            });
        Assert.Equal(0, code);
        Assert.Contains("\"state\":\"healthy\"", output.ToString());
    }

    [Fact]
    public async Task ForegroundFailedHealthReturnsErrorCodeWithAssessment()
    {
        var session = new MonitorControlSession(false, () => { });
        session.MarkStarted();
        session.Publish(Counters(Good with { NativeStarted = false, LastPacketUtc = null }));
        using var output = new StringWriter();
        using var error = new StringWriter();
        int code = await CliApplication.RunAsync(new[] { "engine", "health", "--json" }, output, error,
            monitorQuery: (q, _) => Task.FromResult(session.Query(q)));
        Assert.Equal(3, code);
        Assert.Contains("native_capture_not_started", output.ToString());
    }

    [Fact]
    public void ServiceSchema2RoundTripsAndRejectsMissingPipelineField()
    {
        string dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, "monitor.json");
        try
        {
            var snapshot = new ServiceHealthSnapshot(2, Guid.NewGuid(), 123, Now.AddMinutes(-1), Now, Counters());
            ServiceHealthStore.Write(path, snapshot);
            Assert.Equal(snapshot, ServiceHealthStore.Read(path));
            Assert.Throws<InvalidDataException>(() => ServiceHealthStore.Validate(snapshot with { SchemaVersion = 1 }));
            string json = File.ReadAllText(path).Replace("\"nativeStarted\":true,", "");
            File.WriteAllText(path, json);
            Assert.Throws<InvalidDataException>(() => ServiceHealthStore.Read(path));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void PipelineJsonRequiresExplicitFields()
    {
        var json = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        string serialized = JsonSerializer.Serialize(Good, json).Replace("\"journalWriteFailures\":0,", "");
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<PipelineTelemetry>(serialized, json));
    }
}
