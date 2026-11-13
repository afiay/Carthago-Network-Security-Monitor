// SPDX-License-Identifier: MIT
using System.Text.Json;
using Carthago.Contracts;
using Carthago.Services.Cli;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class LiveInvestigationTests
{
    private const string A = "00000000000000000000000000000001";
    private const string B = "00000000000000000000000000000002";
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task JournalReadsActualCamelCaseAndFiltersWithoutEvidence()
    {
        await WithJournal(Row(A, "High") + Row(B, "Low"), async path =>
        {
            var page = await DetectionJournalQuery.ReadAsync(path, new(Severity: "high", SourceIp: "192.168.1.10"), default);
            Assert.NotNull(page);
            var row = Assert.Single(page!.Rows);
            Assert.Equal(A, row.Id);
            Assert.Equal("high", row.Severity);
            Assert.Equal(Now, row.ObservedUtc);
            Assert.Equal("persisted", row.Status);
            Assert.DoesNotContain("SECRET", JsonSerializer.Serialize(page));
        });
    }

    [Fact]
    public async Task MissingJournalIsUnavailable()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Assert.Null(await DetectionJournalQuery.ReadAsync(path, new(), default));
    }

    [Theory]
    [InlineData("{}\n")]
    [InlineData("{\"eventId\":\"00000000000000000000000000000001\"}")]
    [InlineData("{\"eventId\":\"00000000000000000000000000000001\",\"EventId\":\"00000000000000000000000000000002\"}\n")]
    public async Task InvalidOrIncompleteJournalFailsClosed(string input)
        => await WithJournal(input, async path =>
            await Assert.ThrowsAsync<InvalidDataException>(() => DetectionJournalQuery.ReadAsync(path, new(), default)));

    [Fact]
    public async Task DuplicateJournalIdentityOutsideFilterRejected()
        => await WithJournal(Row(A, "High") + Row(A, "Low"), async path =>
            await Assert.ThrowsAsync<InvalidDataException>(() => DetectionJournalQuery.ReadAsync(path, new(Severity: "critical"), default)));

    [Fact]
    public async Task OversizedJournalRejectedBeforeParsing()
    {
        await WithJournal("", async path =>
        {
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Write))
                stream.SetLength(DetectionJournalQuery.MaxBytes + 1L);
            await Assert.ThrowsAsync<InvalidDataException>(() => DetectionJournalQuery.ReadAsync(path, new(), default));
        });
    }

    [Fact]
    public void ResponseRejectsMismatchedCorrelationAndFilter()
    {
        var q = new InvestigationRequest(3, Guid.NewGuid(), InvestigationKind.Alerts, new(Severity: "high"));
        var page = InvestigationProjection.Select(new[] { JsonSerializer.SerializeToElement(new { EventId = A, Severity = "High" }) },
            q.Kind, q.Filter, default);
        var r = new InvestigationResponse(3, q.Correlation, q.Kind, LiveQueryState.Available, Now, page);
        InvestigationProtocol.ValidateResponse(r, q);
        Assert.Throws<InvalidDataException>(() => InvestigationProtocol.ValidateResponse(r with { Correlation = Guid.NewGuid() }, q));
        Assert.Throws<InvalidDataException>(() => InvestigationProtocol.ValidateResponse(r with
        { Page = page with { Rows = new[] { page.Rows[0] with { Severity = "low" } } } }, q));
        Assert.Throws<InvalidDataException>(() => InvestigationProtocol.ValidateResponse(r with { State = LiveQueryState.Unavailable }, q));
    }

    [Fact]
    public async Task CliLiveSourceIsExplicitAndMissingDoesNotReportZero()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        int code = await CliApplication.RunAsync(new[] { "alerts", "list", "--live", "--severity", "high", "--json" },
            output, error, investigationQuery: (q, _) => Task.FromResult(new InvestigationResponse(3, q.Correlation, q.Kind,
                LiveQueryState.Available, Now, new InvestigationPage(0, q.Filter.Offset, q.Filter.Limit, 0, Array.Empty<InvestigationRow>()))));
        Assert.Equal(0, code);
        Assert.Contains("current_utc_day_detection_journal", output.ToString());
        output.GetStringBuilder().Clear();
        code = await CliApplication.RunAsync(new[] { "incidents", "list", "--live", "--json" }, output, error,
            investigationQuery: (q, _) => Task.FromResult(new InvestigationResponse(3, q.Correlation, q.Kind, LiveQueryState.Unavailable, Now)));
        Assert.Equal(3, code);
        Assert.Empty(output.ToString());
        Assert.Contains("source_unavailable", error.ToString());
    }

    [Fact]
    public async Task WindowsV3LoopbackCandidate()
    {
        if (!OperatingSystem.IsWindows()) return;
        string name = "Carthago.Test.V3." + Guid.NewGuid().ToString("N");
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var server = WindowsLocalReadPipe.ServeInvestigationAsync((q, _) => Task.FromResult(new InvestigationResponse(3,
            q.Correlation, q.Kind, LiveQueryState.Available, Now,
            new InvestigationPage(0, q.Filter.Offset, q.Filter.Limit, 0, Array.Empty<InvestigationRow>()))), cts.Token, name);
        try
        {
            var q = new InvestigationRequest(3, Guid.NewGuid(), InvestigationKind.Alerts, new());
            Assert.Equal(0, (await WindowsLocalReadPipe.QueryInvestigationAsync(q, cts.Token, name)).Page!.Total);
            Assert.Equal(0, (await WindowsLocalReadPipe.QueryInvestigationAsync(q with { Correlation = Guid.NewGuid() }, cts.Token, name)).Page!.Total);
        }
        finally
        {
            cts.Cancel();
            try { await server; } catch (OperationCanceledException) when (cts.IsCancellationRequested) { }
        }
    }

    private static string Row(string id, string severity) => JsonSerializer.Serialize(new
    {
        eventId = id, timestampUtc = Now, ruleId = "R001", severity, sourceIp = "192.168.1.10",
        deliveryStatus = "Persisted", evidence = "SECRET"
    }) + "\n";

    private static async Task WithJournal(string input, Func<string, Task> test)
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".jsonl");
        try { await File.WriteAllTextAsync(path, input); await test(path); }
        finally { File.Delete(path); }
    }
}
