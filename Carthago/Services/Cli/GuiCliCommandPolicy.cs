// SPDX-License-Identifier: MIT
using System;
using System.Linq;

namespace Carthago.Services.Cli;

internal enum GuiCliLocalAction { None, Help, Clear }

// Explicitly read-only CARTHAGO commands. This is not a PowerShell/cmd shell,
// does not accept filesystem paths or process invocation, and cannot start,
// stop, configure, or authorize monitoring/sensors.
internal static class GuiCliCommandPolicy
{
    internal const int MaxInputLength = 256;
    internal static bool TryParse(string? input, out string[] arguments, out GuiCliLocalAction localAction)
    {
        arguments = Array.Empty<string>();
        localAction = GuiCliLocalAction.None;
        if (string.IsNullOrWhiteSpace(input) || input.Length > MaxInputLength ||
            input.Any(char.IsControl))
            return false;

        var parts = input.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length > 12) return false;
        if (parts.Length > 0 && string.Equals(parts[0], "carthago", StringComparison.OrdinalIgnoreCase))
            parts = parts.Skip(1).ToArray();
        if (parts.Length == 1 && parts[0] is "help" or "--help" or "-h")
        {
            localAction = GuiCliLocalAction.Help;
            return true;
        }
        if (parts is ["clear"])
        {
            localAction = GuiCliLocalAction.Clear;
            return true;
        }

        var json = parts.Length > 0 && parts[^1] == "--json";
        var command = json ? parts[..^1] : parts;
        var permitted = command switch
        {
            ["engine", "status"] => true,
            ["rules", "summary"] => true,
            ["rules", "validate"] => true,
            ["rules", "list", "--live"] => true,
            ["rules", "list", "--live", "--offset", var ruleOffsetText, "--limit", var ruleLimitText]
                when int.TryParse(ruleOffsetText, out var ruleOffset) && ruleOffset >= 0 &&
                     int.TryParse(ruleLimitText, out var ruleLimit) && ruleLimit is >= 1 and <= 100 => true,
            ["rules", "show", var id, "--live"]
                when id.Length is >= 4 and <= 6 && id[0] == 'R' &&
                     id.Skip(1).All(c => c is >= '0' and <= '9') => true,
            ["sensors", "list"] => true,
            ["sensors", "list", "--offset", var sensorOffsetText, "--limit", var sensorLimitText]
                when int.TryParse(sensorOffsetText, out var sensorOffset) && sensorOffset >= 0 &&
                     int.TryParse(sensorLimitText, out var sensorLimit) && sensorLimit is >= 1 and <= 100 => true,
            ["sensors", "health"] => true,
            ["alerts", "list", "--live"] => true,
            ["incidents", "list", "--live"] => true,
            ["events", "list", "--live"] => true,
            ["hosts", "list", "--live"] => true,
            ["capture", "doctor"] => true,
            ["capture", "interfaces"] => true,
            _ => false
        };
        if (!permitted) return false;
        arguments = parts;
        return true;
    }

    internal const string HelpText =
        "Read-only CARTHAGO commands (optional prefix: carthago):\n" +
        "  engine status | rules summary | rules validate\n" +
        "  rules list --live [--offset N --limit N]\n" +
        "  rules show R123 --live\n" +
        "  sensors list [--offset N --limit N] | sensors health\n" +
        "  alerts list --live | incidents list --live\n" +
        "  events list --live | hosts list --live\n" +
        "  capture doctor | capture interfaces\n" +
        "  help | clear\n" +
        "Append --json to a supported CARTHAGO command.\n" +
        "This panel is NOT a system shell; service changes, capture, and stop commands are unavailable.";
}
