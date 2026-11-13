// SPDX-License-Identifier: MIT
using System.Globalization;

namespace Carthago.Contracts;

public sealed record JournalWindow(DateTimeOffset StartUtc, DateTimeOffset EndUtc)
{
    public static bool TryDate(string? value, out DateOnly date) =>
        DateOnly.TryParseExact(value, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out date);

    public static bool TryDuration(string? value, out int minutes)
    {
        minutes = 0;
        if (value is not { Length: >= 2 and <= 5 } ||
            !int.TryParse(value.AsSpan(0, value.Length - 1), NumberStyles.None, CultureInfo.InvariantCulture, out int n))
            return false;
        if (value[^1] == 'h' && n is >= 1 and <= 24) minutes = n * 60;
        else if (value[^1] == 'm' && n is >= 1 and <= 1440) minutes = n;
        return minutes > 0;
    }

    public static JournalWindow Resolve(InvestigationFilter filter, DateTimeOffset now)
    {
        now = now.ToUniversalTime();
        if (filter.SinceMinutes is int minutes)
        {
            if (minutes is < 1 or > 1440 || filter.JournalDate is not null)
                throw new InvalidDataException("Invalid journal window.");
            return new(now.AddMinutes(-minutes), now);
        }
        var day = DateOnly.FromDateTime(now.UtcDateTime);
        if (filter.JournalDate is not null && (!TryDate(filter.JournalDate, out day) ||
            day > DateOnly.FromDateTime(now.UtcDateTime) || day == DateOnly.MaxValue))
            throw new InvalidDataException("Invalid journal date.");
        var start = new DateTimeOffset(day.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc));
        return new(start, start.AddDays(1));
    }

    public bool Contains(DateTimeOffset time) => time >= StartUtc && time < EndUtc;

    public IEnumerable<DateTime> Days()
    {
        for (var day = StartUtc.UtcDateTime.Date; day < EndUtc.UtcDateTime; day = day.AddDays(1))
            yield return day;
    }
}
