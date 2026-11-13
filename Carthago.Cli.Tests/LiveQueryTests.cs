// SPDX-License-Identifier: MIT
using Carthago.Contracts;
using Carthago.Services.Cli;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class LiveQueryTests
{
    private static LiveQuery Query(LiveQueryKind kind, int offset = 0, int limit = 1, string? id = null)
        => new(2, Guid.NewGuid(), kind, offset, limit, id);

    [Fact]
    public async Task FrameRoundTripAndCorrelation()
    {
        var q = Query(LiveQueryKind.RulesList, limit: 2);
        using var stream = new MemoryStream();
        await LiveQueryProtocol.WriteAsync(stream, q, LiveQueryProtocol.MaxRequestBytes, default);
        stream.Position = 0;
        Assert.Equal(q, await LiveQueryProtocol.ReadAsync<LiveQuery>(stream, LiveQueryProtocol.MaxRequestBytes, default));
        var r = new LiveQueryResult(2, q.Correlation, q.Kind, LiveQueryState.Available, DateTimeOffset.UtcNow,
            Total: 1, Rules: new[] { new LiveRuleRow("R001", "Scan", "Network", "High", true, false) });
        LiveQueryProtocol.ValidateResult(r, q);
        Assert.Throws<InvalidDataException>(() => LiveQueryProtocol.ValidateResult(r with { Correlation = Guid.NewGuid() }, q));
    }

    [Fact]
    public async Task OversizeFrameRejectedBeforeBody()
    {
        using var stream = new MemoryStream(new byte[] { 0, 0, 16, 0 });
        await Assert.ThrowsAsync<InvalidDataException>(() => LiveQueryProtocol.ReadAsync<LiveQuery>(stream, 1024, default));
    }

    [Fact]
    public void RejectInvalidRequestAndResult()
    {
        var q = Query(LiveQueryKind.RulesList, limit: 101);
        Assert.Throws<InvalidDataException>(() => LiveQueryProtocol.ValidateQuery(q));
        q = Query(LiveQueryKind.RuleShow, id: "R001");
        var response = new LiveQueryResult(2, q.Correlation, q.Kind, LiveQueryState.Available, DateTimeOffset.UtcNow,
            Total: 1, Rules: new[] { new LiveRuleRow("R002", "Wrong", "Network", "High", true, false) });
        Assert.Throws<InvalidDataException>(() => LiveQueryProtocol.ValidateResult(response, q));
        Assert.Throws<InvalidDataException>(() => LiveQueryProtocol.ValidateResult(response with { State = LiveQueryState.Unavailable }, q));
    }

    [Fact]
    public async Task SensorProjectionUsesLatestTimestampAndExplicitFreshness()
    {
        string dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var now = new DateTimeOffset(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(dir, "heartbeats-2026-11-13.jsonl"),
                Row("A", now.AddMinutes(-1)) + Row("A", now.AddHours(-1)) +
                Row("B", now.AddMinutes(-6)) + Row("C", now.AddMinutes(1)));
            await File.WriteAllTextAsync(Path.Combine(dir, "heartbeats-2026-11-12.jsonl"), Row("A", now.AddDays(-1)));
            var rows = await SensorHeartbeatReadProjection.ReadAsync(dir, now, default);
            Assert.NotNull(rows);
            Assert.Equal(new[] { "fresh", "stale", "future" }, rows!.Select(r => r.Freshness));
            Assert.Equal(now.AddMinutes(-1), rows[0].LastHeartbeatUtc);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task MissingJournalIsUnavailableAndMalformedJournalFails()
    {
        string dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        var now = new DateTimeOffset(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);
        Assert.Null(await SensorHeartbeatReadProjection.ReadAsync(dir, now, default));
        Directory.CreateDirectory(dir);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(dir, "heartbeats-2026-11-13.jsonl"), "{}");
            await Assert.ThrowsAsync<InvalidDataException>(() => SensorHeartbeatReadProjection.ReadAsync(dir, now, default));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task CliLiveRuleQueryDoesNotClaimQualification()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        int code = await CliApplication.RunAsync(new[] { "rules", "show", "R001", "--live", "--json" },
            output, error, liveQuery: (q, _) => Task.FromResult(new LiveQueryResult(2, q.Correlation, q.Kind,
                LiveQueryState.Available, DateTimeOffset.UtcNow, Total: 1,
                Rules: new[] { new LiveRuleRow("R001", "Scan", "Network", "High", true, false) })));
        Assert.Equal(0, code);
        Assert.Contains("not_assessed", output.ToString());
        Assert.Empty(error.ToString());
    }

    [Fact]
    public async Task CliSensorUnavailableDoesNotReportZero()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        int code = await CliApplication.RunAsync(new[] { "sensors", "health", "--json" }, output, error,
            liveQuery: (q, _) => Task.FromResult(new LiveQueryResult(2, q.Correlation, q.Kind,
                LiveQueryState.Unavailable, DateTimeOffset.UtcNow)));
        Assert.Equal(3, code);
        Assert.Empty(output.ToString());
        Assert.Contains("source_unavailable", error.ToString());
    }

    [Fact]
    public async Task WindowsV2LoopbackCandidate()
    {
        if (!OperatingSystem.IsWindows()) return;
        string name = "Carthago.Test.V2." + Guid.NewGuid().ToString("N");
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var server = WindowsLocalReadPipe.ServeLiveAsync((q, _) => Task.FromResult(new LiveQueryResult(2,
            q.Correlation, q.Kind, LiveQueryState.Available, DateTimeOffset.UtcNow, CatalogErrors: 0)), cts.Token, name);
        try
        {
            var r = await WindowsLocalReadPipe.QueryLiveAsync(Query(LiveQueryKind.RulesValidate), cts.Token, name);
            Assert.Equal(0, r.CatalogErrors);
            var second = await WindowsLocalReadPipe.QueryLiveAsync(Query(LiveQueryKind.RulesValidate), cts.Token, name);
            Assert.Equal(0, second.CatalogErrors);
        }
        finally
        {
            cts.Cancel();
            try { await server; } catch (OperationCanceledException) when (cts.IsCancellationRequested) { }
        }
    }

    private static string Row(string id, DateTimeOffset time) =>
        System.Text.Json.JsonSerializer.Serialize(new { SensorId = id, TimestampUtc = time }) + "\n";
}
