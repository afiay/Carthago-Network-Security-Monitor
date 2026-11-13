// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Diagnostics;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Contracts;
using Carthago.Services;

namespace Carthago.Monitor;

internal sealed class WindowsMonitorService : ServiceBase
{
    internal const string Name = "CarthagoMonitor";
    private const int ServiceFailure = 1064; // ERROR_EXCEPTION_IN_SERVICE
    private readonly string _configPath;
    private ServiceMonitorRun? _run;
    private int _stopRequested;

    public WindowsMonitorService(string configPath)
    {
        _configPath = configPath;
        ServiceName = Name;
        CanStop = true;
        CanShutdown = true;
        AutoLog = false; // No implicit event source registration or sensitive log payload.
    }

    protected override void OnStart(string[] args)
    {
        // The persistent ImagePath config is authoritative; reject one-off SCM overrides.
        if (args.Length != 0) throw new InvalidOperationException("Unexpected service start arguments.");
        Interlocked.Exchange(ref _stopRequested, 0);
        ExitCode = 0;
        RequestAdditionalTime(45000);
        try
        {
            var options = MonitorServiceConfiguration.Load(_configPath);
            string statusPath = ServiceHealthStore.DefaultPath;
            ServiceHealthStore.CheckPath(statusPath);
            using var process = Process.GetCurrentProcess();
            var processStarted = new DateTimeOffset(process.StartTime.ToUniversalTime());
            int pid = process.Id;
            Guid session = Guid.NewGuid();
            _run = new ServiceMonitorRun(options, async token =>
            {
                PreferencesService.Load();
                await PortServiceResolver.InitializeAsync().ConfigureAwait(false);
                token.ThrowIfCancellationRequested();
                return new NpcapForegroundCapture();
            }, TextWriter.Null, sample: counters => ServiceHealthStore.Write(statusPath,
                new ServiceHealthSnapshot(2, session, pid, processStarted, DateTimeOffset.UtcNow, counters)));
            _run.Started.WaitAsync(TimeSpan.FromSeconds(30)).GetAwaiter().GetResult();
            // An unexpected worker exit is a process failure, not a healthy idle service.
            // Worker cleanup has completed before this continuation runs.
            _ = _run.Completion.ContinueWith(t =>
            {
                _ = t.Exception;
                if (Volatile.Read(ref _stopRequested) == 0)
                    Environment.Exit(3);
            }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
        catch
        {
            ExitCode = ServiceFailure;
            Interlocked.Exchange(ref _stopRequested, 1);
            if (_run is not null)
            {
                _run.RequestStop();
                try { _run.Completion.WaitAsync(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult(); }
                catch { /* startup failed; never advertise running */ }
                if (!_run.Completion.IsCompleted) Environment.Exit(3);
            }
            throw;
        }
    }

    protected override void OnStop()
    {
        RequestAdditionalTime(30000);
        StopWorker();
    }

    protected override void OnShutdown() => StopWorker();

    private void StopWorker()
    {
        Interlocked.Exchange(ref _stopRequested, 1);
        var run = _run;
        if (run is null) return;
        try
        {
            run.RequestStop();
            int code = run.Completion.WaitAsync(TimeSpan.FromSeconds(20)).GetAwaiter().GetResult();
            if (code != 130) throw new InvalidOperationException("Capture worker shutdown failed.");
            run.Dispose();
            _run = null;
            ExitCode = 0;
        }
        catch
        {
            ExitCode = ServiceFailure;
            // Do not claim a clean stop if native capture or worker shutdown is blocked.
            throw;
        }
    }
}
