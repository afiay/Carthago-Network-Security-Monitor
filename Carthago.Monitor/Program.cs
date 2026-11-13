// SPDX-License-Identifier: MIT
using System.Text.Json;
using System.Windows.Threading;
using Carthago.Contracts;
using Carthago.Services;
using SharpPcap;

namespace Carthago.Monitor;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        var output = Console.Out;
        var error = Console.Error;
        if (args.Length == 0 || args is ["--help"] or ["-h"])
        {
            output.WriteLine("CARTHAGO foreground monitor (Windows/Npcap)\n" +
                "  carthago-monitor capture interfaces [--json]\n" +
                "  carthago-monitor monitor start --interface ID [--filter BPF] [--status-seconds N] [--json]\n" +
                "Ctrl+C stops monitoring. Close the desktop monitor before starting. No remote enrichment or external sinks.");
            return 0;
        }
        if (args is ["capture", "interfaces"] or ["capture", "interfaces", "--json"])
        {
            try
            {
                var rows = CaptureDeviceList.Instance.Select(d => new { id = d.Name, description = d.Description })
                    .Where(d => !string.IsNullOrWhiteSpace(d.id)).ToArray();
                if (args[^1] == "--json") output.WriteLine(JsonSerializer.Serialize(new { schemaVersion = 1, interfaces = rows }));
                else foreach (var row in rows) output.WriteLine(JsonSerializer.Serialize(row));
                return 0;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                error.WriteLine("Npcap interface enumeration unavailable.");
                return 3;
            }
        }
        if (!ForegroundMonitor.TryParse(args, out var options))
        {
            error.WriteLine("Invalid command. Use --help.");
            return 2;
        }

        // Mutex protects foreground instances in this Windows session only.
        // Desktop is not covered: operator must close it first.
        using var ownership = new Mutex(false, @"Local\Carthago.ForegroundMonitor.v1");
        bool acquired;
        try { acquired = ownership.WaitOne(0); }
        catch (AbandonedMutexException) { acquired = true; }
        if (!acquired) { error.WriteLine("Another foreground monitor is active."); return 3; }
        try { return RunMonitorAsync(options!, output, error).GetAwaiter().GetResult(); }
        finally { ownership.ReleaseMutex(); }
    }

    private static async Task<int> RunMonitorAsync(ForegroundMonitorOptions options, TextWriter output, TextWriter error)
    {
        using var cancel = new CancellationTokenSource();
        ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; cancel.Cancel(); };
        Console.CancelKeyPress += handler;
        // Existing engine writes free-text detections to Console.Out. Keep structured
        // monitor stdout independent; persisted journal remains the source of evidence.
        Console.SetOut(TextWriter.Null);
        try
        {
            PreferencesService.Load();
            await PortServiceResolver.InitializeAsync();
            cancel.Token.ThrowIfCancellationRequested();
            var capture = new NpcapForegroundCapture();
            return await ForegroundMonitor.RunAsync(capture, options, output, error, cancel.Token);
        }
        catch (OperationCanceledException) when (cancel.IsCancellationRequested) { return 130; }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            error.WriteLine("Foreground monitor initialization failed.");
            return 3;
        }
        finally
        {
            Console.CancelKeyPress -= handler;
            Console.SetOut(output);
        }
    }
}

internal sealed class NpcapForegroundCapture : IForegroundCapture
{
    private readonly TrafficCaptureService _capture = new(null, Dispatcher.CurrentDispatcher, headless: true);
    public void Start(string interfaceId, string? filter)
    {
        var matches = CaptureDeviceList.Instance.Where(d => string.Equals(d.Name, interfaceId, StringComparison.Ordinal)).ToArray();
        if (matches.Length != 1) throw new InvalidOperationException("Unknown or ambiguous interface.");
        _capture.StartHeadlessNpcap(matches[0], filter);
    }
    public bool CaptureRequested => _capture.GetCaptureSourceHealth().Running;
    public ForegroundMonitorCounters ReadCounters()
    {
        var stats = _capture.GetStats();
        return new(stats.PacketsCaptured, stats.PacketsParsedOk, stats.PacketsParseErrors, stats.RuleEventsRaised);
    }
    public async ValueTask DisposeAsync()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await _capture.StopHeadlessAsync(deadline.Token);
    }
}
