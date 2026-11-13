// SPDX-License-Identifier: MIT
using System.Net;
using System.Text.Json;

namespace Carthago.Contracts;

public enum InvestigationKind { Alerts, Incidents, Events, Hosts }
public sealed record InvestigationFilter(int Offset = 0, int Limit = 50, string? Severity = null,
    string? SourceIp = null, string? Id = null);
public sealed record InvestigationRow(string? Id, DateTimeOffset? ObservedUtc, string? RuleId,
    string? Severity, string? SourceIp, string? DestinationIp, int? SourcePort, int? DestinationPort,
    string? Protocol, string? Status, int? RiskScore, int? OccurrenceCount, int? Length);
public sealed record InvestigationPage(int Total, int Offset, int Limit, int OmittedRows,
    IReadOnlyList<InvestigationRow> Rows);

/// <summary>Passive, fixed-field projection of saved or local journal/cache data. Never reconstructs trusted events.</summary>
public static class InvestigationProjection
{
    public static bool IsId(string? value) => value is { Length: > 0 } &&
        (Guid.TryParseExact(value, "N", out _) || Guid.TryParseExact(value, "D", out _));

    public static string? NormalizeIp(string? value)
    {
        if (value is not { Length: > 0 and <= 64 } || value.Contains('%') ||
            !IPAddress.TryParse(value, out var ip)) return null;
        // Reject abbreviated, hexadecimal and octal IPv4 input accepted by IPAddress.TryParse.
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
            !string.Equals(ip.ToString(), value, StringComparison.Ordinal)) return null;
        return ip.ToString();
    }

    public static string? NormalizeSeverity(string? value) => value?.ToLowerInvariant() switch
    {
        "info" => "info", "low" => "low", "medium" => "medium", "high" => "high", "critical" => "critical", _ => null
    };

    public static void ValidateFilter(InvestigationKind kind, InvestigationFilter filter)
    {
        if (!Enum.IsDefined(kind) || filter.Offset < 0 || filter.Limit is < 1 or > 100 ||
            (filter.Severity is not null && (NormalizeSeverity(filter.Severity) is null ||
                kind is not (InvestigationKind.Alerts or InvestigationKind.Incidents))) ||
            (filter.SourceIp is not null && NormalizeIp(filter.SourceIp) is null) ||
            (filter.Id is not null && (!IsId(filter.Id) || kind is not (InvestigationKind.Alerts or InvestigationKind.Incidents))))
            throw new ArgumentException("Invalid investigation filter.");
    }

    public static InvestigationPage Select(IEnumerable<JsonElement> rows, InvestigationKind kind,
        InvestigationFilter filter, CancellationToken token)
    {
        ValidateFilter(kind, filter);
        string? severity = NormalizeSeverity(filter.Severity);
        string? sourceIp = NormalizeIp(filter.SourceIp);
        var page = new List<InvestigationRow>(filter.Limit);
        var ids = new HashSet<Guid>();
        int total = 0, omitted = 0;
        foreach (var raw in rows)
        {
            token.ThrowIfCancellationRequested();
            var row = Project(raw, kind);
            if (row is null) { omitted++; continue; }
            // IDs must be unique for unambiguous show, even outside the selected filter.
            if (kind != InvestigationKind.Hosts &&
                !ids.Add(Guid.Parse(row.Id!)))
                throw new InvalidDataException("Duplicate investigation identity.");
            if (severity is not null && row.Severity != severity) continue;
            if (sourceIp is not null && row.SourceIp != sourceIp) continue;
            if (filter.Id is not null && Guid.Parse(row.Id!) != Guid.Parse(filter.Id)) continue;
            if (total >= filter.Offset && page.Count < filter.Limit) page.Add(row);
            total++;
        }
        return new InvestigationPage(total, filter.Offset, filter.Limit, omitted, page);
    }

    private static InvestigationRow? Project(JsonElement row, InvestigationKind kind)
    {
        if (row.ValueKind != JsonValueKind.Object) return null;
        // Reject ambiguous object fields, including case variants; never echo arbitrary values.
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in row.EnumerateObject())
            if (!names.Add(p.Name)) throw new InvalidDataException("Ambiguous investigation row.");
        string? id = null, rule = null, severity = null, source = null, destination = null,
            protocol = null, status = null;
        DateTimeOffset? time = null;
        int? sourcePort = null, destinationPort = null, risk = null, count = null, length = null;
        switch (kind)
        {
            case InvestigationKind.Alerts:
                id = Text(row, "EventId");
                if (!IsId(id)) return null;
                time = Utc(row, "TimestampUtc");
                rule = Rule(Text(row, "RuleId"));
                severity = NormalizeSeverity(Text(row, "Severity"));
                source = NormalizeIp(Text(row, "SourceIp"));
                destination = NormalizeIp(Text(row, "DestinationIp"));
                sourcePort = Number(row, "SourcePort", 0, 65535);
                destinationPort = Number(row, "DestinationPort", 0, 65535);
                protocol = Protocol(Text(row, "Protocol"));
                status = Fixed(Text(row, "DeliveryStatus"), "pending", "persisted", "delivered", "failed", "failedtopersist");
                break;
            case InvestigationKind.Incidents:
                id = Text(row, "Id");
                if (!IsId(id)) return null;
                if (Property(row, "IncidentId", out _) &&
                    (!IsId(Text(row, "IncidentId")) || Guid.Parse(id!) != Guid.Parse(Text(row, "IncidentId")!)))
                    throw new InvalidDataException("Conflicting incident identities.");
                time = Utc(row, "UpdatedUtc");
                rule = Rule(Text(row, "PrimaryRuleId"));
                severity = NormalizeSeverity(Text(row, "Severity"));
                source = NormalizeIp(Text(row, "PrimarySourceIp"));
                destination = NormalizeIp(Text(row, "PrimaryDestinationIp"));
                status = Fixed(Text(row, "Status"), "new", "acknowledged", "investigating", "resolved");
                risk = Number(row, "RiskScore", 0, int.MaxValue);
                count = Number(row, "OccurrenceCount", 0, int.MaxValue);
                break;
            case InvestigationKind.Events:
                id = Text(row, "Id");
                if (!IsId(id)) return null;
                // TrafficRecord.Timestamp is a display string; do not infer a UTC instant.
                source = NormalizeIp(Text(row, "Source"));
                destination = NormalizeIp(Text(row, "Destination"));
                sourcePort = Number(row, "SourcePort", 0, 65535);
                destinationPort = Number(row, "DestinationPort", 0, 65535);
                protocol = Protocol(Text(row, "Protocol"));
                length = Number(row, "Length", 0, int.MaxValue);
                break;
            case InvestigationKind.Hosts:
                source = NormalizeIp(Text(row, "Host"));
                if (source is null) return null; // Hostnames and arbitrary labels are not exposed.
                time = Utc(row, "LastSeenUtc");
                break;
        }
        return new InvestigationRow(id is null ? null : Guid.Parse(id).ToString("N"), time, rule, severity,
            source, destination, sourcePort, destinationPort, protocol, status, risk, count, length);
    }

    private static bool Property(JsonElement row, string key, out JsonElement value)
    {
        foreach (var property in row.EnumerateObject())
            if (string.Equals(property.Name, key, StringComparison.OrdinalIgnoreCase))
            { value = property.Value; return true; }
        value = default; return false;
    }

    private static string? Text(JsonElement row, string key)
        => Property(row, key, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;

    public static bool IsRuleId(string value) => Rule(value) == value;
    public static bool IsProtocol(string value) => Protocol(value) == value;
    public static bool IsStatus(InvestigationKind kind, string value) =>
        kind == InvestigationKind.Alerts ? Fixed(value, "pending", "persisted", "delivered", "failed", "failedtopersist") == value :
        kind == InvestigationKind.Incidents && Fixed(value, "new", "acknowledged", "investigating", "resolved") == value;

    private static string? Rule(string? value)
        => value is { Length: >= 4 and <= 13 } && value[0] is >= 'A' and <= 'Z' &&
            value.All(c => c is >= 'A' and <= 'Z' or >= '0' and <= '9') &&
            value.TakeLast(3).All(c => c is >= '0' and <= '9') ? value : null;

    private static string? Fixed(string? value, params string[] allowed)
        => value is not null && allowed.Contains(value, StringComparer.OrdinalIgnoreCase)
            ? value.ToLowerInvariant() : null;

    private static string? Protocol(string? value) => Fixed(value, "tcp", "udp", "icmp", "icmpv6", "arp", "ipv4", "ipv6",
        "dns", "http", "https", "tls", "quic", "smb", "ssh", "mqtt", "dhcp", "ntp");

    private static int? Number(JsonElement row, string key, int min, int max)
        => Property(row, key, out var p) && p.ValueKind == JsonValueKind.Number &&
            p.TryGetInt32(out int n) && n >= min && n <= max ? n : null;

    private static DateTimeOffset? Utc(JsonElement row, string key)
    {
        string? text = Text(row, key);
        if (text is null || !(text.EndsWith("Z", StringComparison.Ordinal) || text.EndsWith("+00:00", StringComparison.Ordinal)))
            return null;
        return Property(row, key, out var value) && value.TryGetDateTimeOffset(out var time) && time.Offset == TimeSpan.Zero && time != default ? time : null;
    }
}
