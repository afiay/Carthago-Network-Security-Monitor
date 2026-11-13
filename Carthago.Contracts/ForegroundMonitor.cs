// SPDX-License-Identifier: MIT
using System.Text.Json;

namespace Carthago.Contracts;

public sealed record ForegroundMonitorOptions(string InterfaceId, string? Filter, int StatusSeconds, bool Json);
public sealed record ForegroundMonitorCounters(long Captured, long Parsed, long ParseErrors, long Detections);
public interface IForegroundCapture : IAsyncDisposable
{
    void Start(string interfaceId, string? filter);
    ForegroundMonitorCounters ReadCounters();
    bool CaptureRequested { get; }
}

public static class ForegroundMonitor
{
    public static bool TryParse(string[] args, out ForegroundMonitorOptions? options)
    {
        options = null;
        if (args.Length < 4 || args[0] != "monitor" || args[1] != "start") return false;
        string? id = null, filter = null;
        int seconds = 5;
        bool json = false;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 2; i < args.Length; i++)
        {
            string key = args[i];
            if (!seen.Add(key)) return false;
            if (key == "--json") { json = true; continue; }
            if (++i >= args.Length) return false;
            string value = args[i];
            switch (key)
            {
                case "--interface":
                    if (!Safe(value, 512) || value.StartsWith("--", StringComparison.Ordinal)) return false;
                    id = value; break;
                case "--filter":
                    if (!Safe(value, 1024) || value.StartsWith("--", StringComparison.Ordinal)) return false;
                    filter = value; break;
                case "--status-seconds":
                    if (!int.TryParse(value, System.Globalization.NumberStyles.None,
                        System.Globalization.CultureInfo.InvariantCulture, out seconds) || seconds is < 1 or > 60) return false;
                    break;
                default: return false;
            }
        }
        if (id is null) return false;
        options = new(id, filter, seconds, json);
        return true;
    }

    private static bool Safe(string value, int max) => value.Length >= 1 && value.Length <= max &&
        !string.IsNullOrWhiteSpace(value) && !value.Any(c => char.IsControl(c) ||
            char.GetUnicodeCategory(c) == System.Globalization.UnicodeCategory.Format);

    public static async Task<int> RunAsync(IForegroundCapture capture, ForegroundMonitorOptions options,
        TextWriter output, TextWriter error, CancellationToken token,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        delay ??= Task.Delay;
        int exit = 0;
        try
        {
            token.ThrowIfCancellationRequested();
            capture.Start(options.InterfaceId, options.Filter);
            while (true)
            {
                token.ThrowIfCancellationRequested();
                if (!capture.CaptureRequested) throw new InvalidOperationException("Capture no longer requested.");
                var counters = capture.ReadCounters();
                // Not a proof of continuous source liveness or lossless capture.
                string state = counters.Captured > 0 ? "capture_observed" : "started_no_packets_observed";
                await output.WriteLineAsync(options.Json ? JsonSerializer.Serialize(new
                {
                    schemaVersion = 1, mode = "foreground_headless", state,
                    observedUtc = DateTimeOffset.UtcNow, counters.Captured, counters.Parsed,
                    counters.ParseErrors, detections = counters.Detections,
                    sourceHealth = "not_assessed", detectionValidation = "not_assessed"
                }, new JsonSerializerOptions(JsonSerializerDefaults.Web)) :
                    $"{state}: captured={counters.Captured}, parsed={counters.Parsed}, parseErrors={counters.ParseErrors}, detections={counters.Detections}");
                await output.FlushAsync();
                await delay(TimeSpan.FromSeconds(options.StatusSeconds), token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { exit = 130; }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            await error.WriteLineAsync("Monitoring failed. Check selected interface, Npcap and permissions.");
            exit = 3;
        }
        finally
        {
            try { await capture.DisposeAsync(); }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                await error.WriteLineAsync("Monitoring shutdown did not complete.");
                exit = 3;
            }
        }
        return exit;
    }
}
