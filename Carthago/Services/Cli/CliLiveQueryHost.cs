// SPDX-License-Identifier: MIT
using Carthago.Contracts;
using Carthago.Engine.Rules.Catalog;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Globalization;
using System.IO;

namespace Carthago.Services.Cli;

internal static class CliLiveQueryHost
{
    internal static async Task<LiveQueryResult> QueryAsync(LiveQuery q, CancellationToken token)
    {
        LiveQueryProtocol.ValidateQuery(q);
        token.ThrowIfCancellationRequested();
        var now = DateTimeOffset.UtcNow;
        LiveQueryResult result = new(LiveQueryProtocol.Version, q.Correlation, q.Kind, LiveQueryState.Available, now);
        switch (q.Kind)
        {
            case LiveQueryKind.RulesList:
            case LiveQueryKind.RuleShow:
                var rules = RuleCatalog.All;
                var selected = q.Kind == LiveQueryKind.RuleShow
                    ? rules.Where(r => r.RuleId == q.RuleId).ToArray()
                    : rules.OrderBy(r => long.Parse(r.RuleId.AsSpan(1), CultureInfo.InvariantCulture))
                        .ThenBy(r => r.RuleId, StringComparer.Ordinal).ToArray();
                if (q.Kind == LiveQueryKind.RuleShow && selected.Length == 0)
                    return result with { State = LiveQueryState.NotFound };
                return result with { Total = selected.Length, Rules = selected.Skip(q.Offset).Take(q.Limit)
                    .Select(r => new LiveRuleRow(r.RuleId, r.Name, r.Category, r.DefaultSeverity.ToString(),
                        r.EnabledByDefault, r.IsPlanned)).ToArray() };
            case LiveQueryKind.RulesValidate:
                // Existing catalog structural checks, not detector replay or accuracy testing.
                return result with { CatalogErrors = RuleCatalog.Validate().Count };
            case LiveQueryKind.SensorsList:
            case LiveQueryKind.SensorsHealth:
                string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "Carthago", "sensors");
                var sensors = await SensorHeartbeatReadProjection.ReadAsync(directory, now, token).ConfigureAwait(false);
                if (sensors is null) return result with { State = LiveQueryState.Unavailable };
                return q.Kind == LiveQueryKind.SensorsList
                    ? result with { Total = sensors.Length, Sensors = sensors.Skip(q.Offset).Take(q.Limit).ToArray() }
                    : result with { Total = sensors.Length, Fresh = sensors.Count(s => s.Freshness == "fresh"),
                        Stale = sensors.Count(s => s.Freshness == "stale"), Future = sensors.Count(s => s.Freshness == "future") };
            default: throw new InvalidDataException("Unknown query.");
        }
    }
}
