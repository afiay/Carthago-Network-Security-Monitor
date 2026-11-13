// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Services.Sensors;

/// <summary>Same-user foreground host; no WPF initialization, capture, service
/// installation or authorization issuance. Public entry for carthago-monitor.</summary>
public static class ActiveSensorWorker
{
    public static Task<int> ExecuteAsync(string[] args, TextWriter output, TextWriter error, CancellationToken token) =>
        ExecuteCoreAsync(args, output, error, token, new ActiveSensorProfileStore(),
            id => LocalLanDiscovery.GetLocalInterfaces(id), () => new ActiveSensorManager());

    private static bool IsId(string value) => value.Length == 64 &&
        value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    internal static async Task<int> ExecuteCoreAsync(string[] args, TextWriter output, TextWriter error,
        CancellationToken token, ActiveSensorProfileStore store,
        Func<Guid, IReadOnlyList<LocalLanInterface>> resolve, Func<ActiveSensorManager> createManager,
        Func<DateTimeOffset>? clock = null, Func<ActiveSensorProfile, bool>? gatewayCurrent = null)
    {
        bool status = args is ["status"] or ["status", "--json"];
        var ids = new List<string>();
        if (!status)
        {
            if (args.Length < 3 || args[0] != "run" || args.Length % 2 != 1 ||
                (args.Length - 1) / 2 > ActiveSensorManager.MaxProfiles)
            { error.WriteLine("Usage: active status [--json] | active run --profile ID [--profile ID ...]"); return 2; }
            for (int i = 1; i < args.Length; i += 2)
            {
                if (args[i] != "--profile" || !IsId(args[i + 1]) || ids.Contains(args[i + 1], StringComparer.Ordinal))
                { error.WriteLine("Invalid or duplicate profile ID."); return 2; }
                ids.Add(args[i + 1]);
            }
        }
        try
        {
            token.ThrowIfCancellationRequested();
            var saved = store.Read();
            if (saved.Error is not null) { error.WriteLine(saved.Error); return 3; }
            if (status)
            {
                var rows = saved.Rows.Select(row =>
                {
                    var grant = row.TryValidate(out var profile) && profile is not null
                        ? store.ReadValidGrant(profile) : null;
                    return new { id = row.Id, sensor = row.Sensor, target = row.Target, adapterId = row.AdapterId,
                        source = row.Source, mask = row.Mask, hostName = row.HostName, port = row.Port,
                        intervalMinutes = row.IntervalMinutes, saveHistory = row.SaveHistory,
                        authorization = grant is null ? "NoValidGrant" : "Valid",
                        expiresUtc = grant is null ? (DateTime?)null : new DateTime(grant.ExpiresTicks, DateTimeKind.Utc) };
                }).ToArray();
                if (args.Length == 2)
                    output.WriteLine(JsonSerializer.Serialize(new { schemaVersion = 1, mode = "configuration-only",
                        liveScopeValidated = false, schedulerRunning = (bool?)null, profiles = rows }));
                else
                {
                    output.WriteLine("Saved configurations only; live scope and scheduler ownership not checked.");
                    foreach (var row in rows) output.WriteLine($"{row.id} | {row.sensor} {row.target} | {row.authorization} | expires {row.expiresUtc:u}");
                }
                return 0;
            }

            // All selected profiles must validate before the manager can run.
            // Never silently skip invalid grants or start an implicit subset.
            var selected = new List<(ActiveSensorProfile Profile, ActiveExecutionGrant Grant)>();
            foreach (var id in ids)
            {
                token.ThrowIfCancellationRequested();
                var row = saved.Rows.SingleOrDefault(r => r.Id == id);
                if (row is null || !row.TryValidate(out var candidate) || candidate is null)
                { error.WriteLine("Selected saved configuration unavailable."); return 3; }
                var live = resolve(candidate.AdapterId).Where(a =>
                    a.Address.Equals(candidate.Adapter.Address) && a.Mask.Equals(candidate.Adapter.Mask) &&
                    LocalLanDiscovery.PlanProbeTargets(new[] { a }).Contains(candidate.Target)).ToArray();
                if (live.Length != 1)
                { error.WriteLine("Selected configuration's live adapter scope is unavailable or ambiguous."); return 3; }
                var profile = row.ApproveForSession(candidate.AdapterId, live[0], candidate.Target);
                if (profile.Kind == ActiveSensorKind.Gateway && !(gatewayCurrent ?? (p => GatewayIntegritySensor.IsConfiguredGateway(p.AdapterId, p.Adapter, p.Target)))(profile))
                { error.WriteLine("Selected target is no longer the configured gateway."); return 3; }
                var grant = store.ReadValidGrant(profile);
                if (grant is null) { error.WriteLine("Selected configuration has no valid durable grant."); return 3; }
                selected.Add((profile, grant));
            }
            var manager = createManager();
            foreach (var item in selected) manager.AddAuthorized(item.Profile, store, item.Grant.GrantId);
            token.ThrowIfCancellationRequested();
            // Exit when all profiles are blocked, or at latest grant expiry.
            // No renewal or new configuration is silently loaded while running.
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            var remaining = new DateTimeOffset(selected.Max(x => x.Grant.ExpiresTicks), TimeSpan.Zero) - (clock ?? (() => DateTimeOffset.UtcNow))();
            if (remaining <= TimeSpan.Zero) { error.WriteLine("Selected grants expired."); return 3; }
            deadline.CancelAfter(remaining);
            output.WriteLine($"Starting {selected.Count} grant-bound profile(s); acquiring scheduler reservation. Ctrl+C stops.");
            try
            {
                await manager.RunAsync(deadline.Token, stopWhenAllBlocked: true).ConfigureAwait(false);
                error.WriteLine("All selected profiles blocked. No further checks.");
                return 3;
            }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested)
            {
                output.WriteLine("Active scheduler stopped; outstanding work completed.");
                return token.IsCancellationRequested ? 130 : 0;
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { return 130; }
        catch (InvalidOperationException ex) { error.WriteLine(ex.Message); return 3; }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        { error.WriteLine("Active worker initialization or execution failed."); return 3; }
    }
}
