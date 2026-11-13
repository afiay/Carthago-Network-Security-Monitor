// SPDX-License-Identifier: MIT
using Carthago.Contracts;
using System.Globalization;
using System.Text.Json;

namespace Carthago.Cli;

/// <summary>Bounded polling, not a lossless subscription. Replay current day then poll appended rows.</summary>
public static class AlertTail
{
    public const int PollSeconds = 2, PageSize = 100, MaxSeen = 20000;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static bool TryParse(string[] command, out InvestigationFilter filter)
    {
        filter = new();
        if (command.Length < 3 || command[0] != "alerts" || command[1] != "tail" || command[2] != "--live") return false;
        // Only severity and source-IP filters, no user-selected cursor or window.
        if ((command.Length - 3) % 2 != 0) return false;
        for (int i = 3; i < command.Length; i += 2)
            if (command[i] is not ("--severity" or "--source-ip")) return false;
        var list = (string[])command.Clone();
        list[1] = "list";
        return InvestigationCommand.TryParse(list, out _, out _, out filter, out _);
    }

    public static async Task RunAsync(InvestigationFilter filter, TextWriter output,
        Func<InvestigationRequest, CancellationToken, Task<InvestigationResponse>> query,
        bool json, CancellationToken token, Func<DateTimeOffset>? clock = null,
        Func<CancellationToken, Task>? delay = null)
    {
        clock ??= () => DateTimeOffset.UtcNow;
        delay ??= t => Task.Delay(TimeSpan.FromSeconds(PollSeconds), t);
        string date = clock().UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        int emitted = 0;
        string? lastId = null;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        while (true)
        {
            token.ThrowIfCancellationRequested();
            if (clock().UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) != date)
                throw new InvalidDataException("UTC day changed; restart tail.");
            // Overlap the previous row to catch truncation or a shifted cursor.
            int offset = Math.Max(0, emitted - 1);
            var request = new InvestigationRequest(InvestigationProtocol.Version, Guid.NewGuid(), InvestigationKind.Alerts,
                filter with { Offset = offset, Limit = PageSize, JournalDate = date, SinceMinutes = null });
            var response = await query(request, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            InvestigationProtocol.ValidateResponse(response, request);
            if (response.State != LiveQueryState.Available)
                throw new InvalidDataException("Journal unavailable; restart tail.");
            var page = response.Page!;
            if (page.Total < emitted || page.Total > MaxSeen ||
                (lastId is not null && (page.Rows.Count == 0 || page.Rows[0].Id != lastId)))
                throw new InvalidDataException("Journal cursor changed; restart tail.");
            foreach (var row in page.Rows.Skip(lastId is null ? 0 : 1))
            {
                token.ThrowIfCancellationRequested();
                if (row.Id is null || !seen.Add(row.Id))
                    throw new InvalidDataException("Duplicate journal cursor; restart tail.");
                await output.WriteLineAsync(json ? JsonSerializer.Serialize(new
                {
                    schemaVersion = 1, provenance = "same_user_local_endpoint",
                    source = "current_utc_day_detection_journal", coverage = "polling_not_lossless",
                    journalDate = date, row
                }, Json) : $"{row.Id} | {row.ObservedUtc:O} | {row.RuleId ?? "-"} | {row.Severity ?? "-"} | {row.SourceIp ?? "-"} -> {row.DestinationIp ?? "-"}");
                await output.FlushAsync();
                lastId = row.Id;
                emitted++;
            }
            if (emitted >= page.Total) await delay(token).ConfigureAwait(false);
        }
    }
}
