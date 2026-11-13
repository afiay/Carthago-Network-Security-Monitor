// SPDX-License-Identifier: MIT
using Carthago.Contracts;

namespace Carthago.Cli;

public static class InvestigationCommand
{
    public static bool TryParse(string[] command, out InvestigationKind kind, out string path,
        out InvestigationFilter filter, out bool show)
    {
        kind = default; path = ""; filter = new(); show = false;
        if (command.Length < 3) return false;
        switch (command[0])
        {
            case "alerts": kind = InvestigationKind.Alerts; break;
            case "incidents": kind = InvestigationKind.Incidents; break;
            case "events": kind = InvestigationKind.Events; break;
            case "hosts": kind = InvestigationKind.Hosts; break;
            default: return false;
        }
        path = command[2];
        if (path != "--live" && (string.IsNullOrWhiteSpace(path) || path.StartsWith("--", StringComparison.Ordinal) ||
            !string.Equals(Path.GetExtension(path), ".csa", StringComparison.OrdinalIgnoreCase))) return false;
        if (command[1] == "show")
        {
            show = true;
            if (kind is not (InvestigationKind.Alerts or InvestigationKind.Incidents) || command.Length != 4 ||
                !InvestigationQueries.IsId(command[3])) return false;
            filter = new InvestigationFilter(Limit: 1, Id: command[3]);
            return true;
        }
        if (command[1] != "list" || (command.Length - 3) % 2 != 0) return false;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        string offset = "0", limit = "50";
        string? severity = null, sourceIp = null, date = null;
        int? since = null;
        for (int i = 3; i < command.Length; i += 2)
        {
            string key = command[i], value = command[i + 1];
            if (!seen.Add(key)) return false;
            switch (key)
            {
                case "--offset": offset = value; break;
                case "--limit": limit = value; break;
                case "--severity":
                    if (kind is not (InvestigationKind.Alerts or InvestigationKind.Incidents) ||
                        (severity = InvestigationQueries.NormalizeSeverity(value)) is null) return false;
                    break;
                case "--date":
                    if (path != "--live" || kind != InvestigationKind.Alerts || !JournalWindow.TryDate(value, out _)) return false;
                    date = value; break;
                case "--since":
                    if (path != "--live" || kind != InvestigationKind.Alerts || !JournalWindow.TryDuration(value, out int minutes)) return false;
                    since = minutes; break;
                case "--source-ip":
                    if ((sourceIp = InvestigationQueries.NormalizeIp(value)) is null) return false;
                    break;
                default: return false;
            }
        }
        if (!OfflineRuleQueries.TryPage(offset, limit, out int start, out int size)) return false;
        if (date is not null && since is not null) return false;
        filter = new InvestigationFilter(start, size, severity, sourceIp, JournalDate: date, SinceMinutes: since);
        return true;
    }
}
