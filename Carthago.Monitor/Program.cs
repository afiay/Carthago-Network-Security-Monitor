// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;
using System.ServiceProcess;
using System.Windows.Threading;
using Carthago.Contracts;
using Carthago.Services;
using Carthago.Services.Cli;
using Carthago.Services.Sensors;
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
                "  carthago-monitor monitor start --interface ID [--filter BPF] [--status-seconds N] [--json] [--enable-cli-ipc] [--allow-cli-stop]\n" +
                "  carthago-monitor active status [--json]\n" +
                "  carthago-monitor active run --profile ID [--profile ID ...]\n" +
                "  carthago-monitor active-service validate --config ABSOLUTE_PATH\n" +
                "  carthago-monitor active-service run --config ABSOLUTE_PATH (SCM only)\n" +
                "  carthago-monitor service validate --config ABSOLUTE_PATH [--json]\n" +
                "  carthago-monitor service run --config ABSOLUTE_PATH (SCM only)\n" +
                "Ctrl+C stops monitoring. Close the desktop monitor before starting. No remote enrichment or external sinks.");
            return 0;
        }
        if (args[0] == "active")
        {
            using var cancel = new CancellationTokenSource();
            ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; cancel.Cancel(); };
            Console.CancelKeyPress += handler;
            try
            {
                return ActiveSensorWorker.ExecuteAsync(args[1..], output, error, cancel.Token)
                    .GetAwaiter().GetResult();
            }
            finally { Console.CancelKeyPress -= handler; }
        }
        if (args is ["active-service", "validate", "--config", var activeConfig])
        {
            try
            {
                var config = ActiveServiceConfiguration.Load(activeConfig);
                output.WriteLine(JsonSerializer.Serialize(new { schemaVersion = 1, configuration = "valid",
                    profileCount = config.Profiles.Count, accountValidated = false, executionValidated = false }));
                return 0;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            { error.WriteLine("Invalid or unavailable active service configuration."); return 3; }
        }
        if (args is ["active-service", "run", "--config", var activePath])
        {
            if (!Path.IsPathFullyQualified(activePath) || Environment.UserInteractive)
            { error.WriteLine("Active service run requires SCM and an absolute configuration path."); return 2; }
            try
            {
                Directory.SetCurrentDirectory(AppContext.BaseDirectory);
                using var service = new WindowsActiveMonitorService(activePath);
                ServiceBase.Run(service);
                return service.ExitCode == 0 ? 0 : 3;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            { error.WriteLine("Active service dispatch or lifecycle failed."); return 3; }
        }
        if (args is ["service", "validate", "--config", _] or
            ["service", "validate", "--config", _, "--json"])
        {
            try
            {
                var config = MonitorServiceConfiguration.Load(args[3]);
                output.WriteLine(args[^1] == "--json" ? JsonSerializer.Serialize(new
                {
                    schemaVersion = 1, configuration = "valid", interfaceId = config.InterfaceId,
                    filterConfigured = config.Filter is not null, statusSeconds = config.StatusSeconds,
                    captureValidated = false
                }) : "Configuration valid; capture permissions and filter have not been tested.");
                return 0;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                error.WriteLine("Invalid or unavailable service configuration.");
                return 3;
            }
        }
        if (args is ["service", "run", "--config", var servicePath])
        {
            if (!Path.IsPathFullyQualified(servicePath) || Environment.UserInteractive)
            {
                error.WriteLine("Service run requires SCM and an absolute configuration path.");
                return 2;
            }
            // SCM normally starts in System32. Resolve bundled engine data from deployment.
            try
            {
                Directory.SetCurrentDirectory(AppContext.BaseDirectory);
                Console.SetOut(TextWriter.Null);
                using var service = new WindowsMonitorService(servicePath);
                ServiceBase.Run(service);
                return service.ExitCode == 0 ? 0 : 3;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                error.WriteLine("Windows service dispatch or lifecycle failed.");
                return 3;
            }
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
        using var listeners = new CancellationTokenSource();
        var tasks = new List<Task>();
        int listenerFailed = 0;
        try
        {
            PreferencesService.Load();
            await PortServiceResolver.InitializeAsync();
            cancel.Token.ThrowIfCancellationRequested();
            MonitorControlSession? session = null;
            if (options.EnableCliIpc)
            {
                session = new MonitorControlSession(options.AllowCliStop, cancel.Cancel);
                // Reserve all default endpoints before capture. No fallback to a partial
                // endpoint set if a desktop/other host already owns a pipe.
                tasks.Add(WindowsLocalReadPipe.ServeAsync(CliReadHost.Query, listeners.Token));
                tasks.Add(WindowsLocalReadPipe.ServeLiveAsync(CliLiveQueryHost.QueryAsync, listeners.Token));
                tasks.Add(WindowsLocalReadPipe.ServeInvestigationAsync(CliInvestigationHost.QueryHeadlessAsync, listeners.Token));
                tasks.Add(WindowsLocalReadPipe.ServeMonitorAsync(session, listeners.Token));
                if (tasks.Any(t => t.IsCompleted)) throw new InvalidOperationException("IPC reservation failed.");
                foreach (var task in tasks)
                    _ = task.ContinueWith(t =>
                    {
                        if (!listeners.IsCancellationRequested)
                        {
                            Interlocked.Exchange(ref listenerFailed, 1);
                            try { cancel.Cancel(); } catch (ObjectDisposedException) { /* process exiting */ }
                        }
                        _ = t.Exception; // Observe failures.
                    }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
            var capture = new NpcapForegroundCapture();
            int result = await ForegroundMonitor.RunAsync(capture, options, output, error, cancel.Token, session: session);
            return Volatile.Read(ref listenerFailed) != 0 ? 3 : result;
        }
        catch (OperationCanceledException) when (cancel.IsCancellationRequested) { return Volatile.Read(ref listenerFailed) != 0 ? 3 : 130; }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            error.WriteLine("Foreground monitor initialization failed.");
            return 3;
        }
        finally
        {
            listeners.Cancel();
            try { await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (Exception ex) when (ex is not OutOfMemoryException) { /* cancellation or endpoint failure */ }
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
        return new(stats.PacketsCaptured, stats.PacketsParsedOk, stats.PacketsParseErrors, stats.RuleEventsRaised,
            _capture.GetHeadlessPipelineTelemetry());
    }
    public async ValueTask DisposeAsync()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await _capture.StopHeadlessAsync(deadline.Token);
    }
}
