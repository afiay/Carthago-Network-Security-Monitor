// SPDX-License-Identifier: MIT
using System.Text.Json;
using Carthago.Contracts;
using Carthago.Services.Cli;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class JournalWindowTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 0, 30, 0, TimeSpan.Zero);
    private const string A = "00000000000000000000000000000001";
    private const string B = "00000000000000000000000000000002";
    private const string C = "00000000000000000000000000000003";

    [Theory]
    [InlineData("1h", 60)]
    [InlineData("24h", 1440)]
    [InlineData("15m", 15)]
    public void DurationAccepted(string input, int expected)
    {
        Assert.True(JournalWindow.TryDuration(input, out int minutes));
        Assert.Equal(expected, minutes);
    }

    [Theory]
    [InlineData("0h")]
    [InlineData("25h")]
    [InlineData("1441m")]
    [InlineData("-1h")]
    [InlineData("1.5h")]
    public void InvalidDurationRejected(string input)
        => Assert.False(JournalWindow.TryDuration(input, out _));

    [Fact]
    public void WindowUsesUtcAndHalfOpenBounds()
    {
        var window = JournalWindow.Resolve(new(SinceMinutes: 60), Now);
        Assert.Equal(Now.AddHours(-1), window.StartUtc);
        Assert.Equal(Now, window.EndUtc);
        Assert.Equal(2, window.Days().Count());
        Assert.True(window.Contains(window.StartUtc));
        Assert.False(window.Contains(window.EndUtc));
        var date = JournalWindow.Resolve(new(JournalDate: "2026-11-12"), Now);
        Assert.Single(date.Days());
        Assert.Throws<InvalidDataException>(() => JournalWindow.Resolve(new(JournalDate: "2026-11-14"), Now));
    }

    [Fact]
    public async Task CrossMidnightWindowFiltersAndRequiresBothFiles()
    {
        string dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        string PathForDay(DateTime day) => Path.Combine(dir, day.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture) + ".jsonl");
        try
        {
            var filter = new InvestigationFilter(SinceMinutes: 60);
            var window = JournalWindow.Resolve(filter, Now);
            string yesterday = PathForDay(Now.UtcDateTime.AddDays(-1));
            string today = PathForDay(Now.UtcDateTime);
            await File.WriteAllTextAsync(yesterday, Row(A, Now.AddMinutes(-61)) + Row(B, Now.AddMinutes(-60)));
            Assert.Null(await DetectionJournalQuery.ReadWindowAsync(PathForDay, filter, window, default));
            await File.WriteAllTextAsync(today, Row(C, Now.AddMinutes(-1)) + Row(Guid.NewGuid().ToString("N"), Now));
            var page = await DetectionJournalQuery.ReadWindowAsync(PathForDay, filter, window, default);
            Assert.Equal(new[] { B, C }, page!.Rows.Select(r => r.Id));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task WindowRejectsMissingTimestamp()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        try
        {
            await File.WriteAllTextAsync(path, "{\"eventId\":\"" + A + "\"}\n");
            var f = new InvestigationFilter(JournalDate: "2026-11-13");
            await Assert.ThrowsAsync<InvalidDataException>(() => DetectionJournalQuery.ReadWindowAsync(_ => path, f, JournalWindow.Resolve(f, Now), default));
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData("alerts list --live --date 2026-02-30")]
    [InlineData("alerts list --live --date 2026-11-12 --since 1h")]
    [InlineData("alerts list file.csa --since 1h")]
    [InlineData("incidents list --live --date 2026-11-12")]
    public void InvalidWindowOptionsRejected(string input)
        => Assert.False(InvestigationCommand.TryParse(input.Split(' '), out _, out _, out _, out _));

    [Fact]
    public async Task TailEmitsEachRecordOnceAndCancels()
    {
        using var output = new StringWriter();
        using var cts = new CancellationTokenSource();
        int polls = 0;
        Task<InvestigationResponse> Query(InvestigationRequest q, CancellationToken _)
        {
            polls++;
            return Task.FromResult(Response(q, polls == 1 ? new[] { A, B } : new[] { A, B, C }));
        }
        Task Delay(CancellationToken token)
        {
            if (polls >= 2) cts.Cancel();
            return Task.CompletedTask;
        }
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            AlertTail.RunAsync(new(), output, Query, true, cts.Token, () => Now, Delay));
        var lines = output.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(3, lines.Length);
        var ids = lines.Select(line => { using var doc = JsonDocument.Parse(line); return doc.RootElement.GetProperty("row").GetProperty("id").GetString(); }).ToArray();
        Assert.Equal(new[] { A, B, C }, ids);
    }

    [Fact]
    public async Task TailRejectsShiftedCursor()
    {
        using var output = new StringWriter();
        int polls = 0;
        await Assert.ThrowsAsync<InvalidDataException>(() => AlertTail.RunAsync(new(), output,
            (q, _) => Task.FromResult(Response(q, ++polls == 1 ? new[] { A, B } : new[] { B, C })), true, default,
            () => Now, _ => Task.CompletedTask));
    }

    [Fact]
    public void LegacyV3RequestOmitsNewFields()
    {
        string json = JsonSerializer.Serialize(new InvestigationRequest(3, Guid.NewGuid(), InvestigationKind.Alerts, new()),
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.DoesNotContain("journalDate", json);
        Assert.DoesNotContain("sinceMinutes", json);
    }

    private static InvestigationResponse Response(InvestigationRequest q, string[] ids)
    {
        var rows = ids.Skip(q.Filter.Offset).Take(q.Filter.Limit)
            .Select(id => new InvestigationRow(id, Now.AddMinutes(-1), "R001", "high", null, null, null, null, null, null, null, null, null)).ToArray();
        return new(3, q.Correlation, q.Kind, LiveQueryState.Available, Now,
            new InvestigationPage(ids.Length, q.Filter.Offset, q.Filter.Limit, 0, rows));
    }

    private static string Row(string id, DateTimeOffset time)
        => JsonSerializer.Serialize(new { eventId = id, timestampUtc = time, severity = "High" }) + "\n";
}
