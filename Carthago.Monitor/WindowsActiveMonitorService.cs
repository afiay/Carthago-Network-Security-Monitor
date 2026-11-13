// SPDX-License-Identifier: MIT
using System.ServiceProcess;
using Carthago.Contracts;
using Carthago.Services.Sensors;

namespace Carthago.Monitor;

internal sealed class WindowsActiveMonitorService : ServiceBase
{
    internal const string Name = "CarthagoActiveMonitor";
    private readonly string _path;
    private ActiveServiceRun? _run;
    private int _stopping;
    internal WindowsActiveMonitorService(string path)
    {
        _path = path; ServiceName = Name; CanStop = true; CanShutdown = true; AutoLog = false;
    }
    protected override void OnStart(string[] args)
    {
        if (args.Length != 0) throw new InvalidOperationException("Unexpected service start arguments.");
        Interlocked.Exchange(ref _stopping, 0);
        ExitCode = 0;
        RequestAdditionalTime(45000);
        try
        {
            var options = ActiveServiceConfiguration.Load(_path);
            _run = new ActiveServiceRun((token, ready) => ActiveServiceWorker.ExecuteAsync(options, token, ready));
            _run.Started.WaitAsync(TimeSpan.FromSeconds(30)).GetAwaiter().GetResult();
            if (_run.Completion.IsCompleted) throw new InvalidOperationException("Active worker exited at startup.");
            _ = _run.Completion.ContinueWith(t =>
            {
                _ = t.Exception;
                if (Volatile.Read(ref _stopping) != 0) return;
                // Expiry or blocked scope ends the service, not a healthy idle state.
                try { Stop(); }
                catch { Environment.Exit(3); }
            }, CancellationToken.None, TaskContinuationOptions.None, TaskScheduler.Default);
        }
        catch
        {
            ExitCode = 1064;
            Interlocked.Exchange(ref _stopping, 1);
            if (_run is not null)
            {
                _run.RequestStop();
                try { _run.Completion.WaitAsync(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult(); }
                catch { }
                if (!_run.Completion.IsCompleted) Environment.Exit(3);
                _run.Dispose(); _run = null;
            }
            throw;
        }
    }
    protected override void OnStop() { RequestAdditionalTime(30000); StopWorker(); }
    protected override void OnShutdown() => StopWorker();
    private void StopWorker()
    {
        Interlocked.Exchange(ref _stopping, 1);
        var run = _run;
        if (run is null) return;
        try
        {
            run.RequestStop();
            int code = run.Completion.WaitAsync(TimeSpan.FromSeconds(20)).GetAwaiter().GetResult();
            ExitCode = code is 0 or 130 ? 0 : 1064;
            run.Dispose(); _run = null;
        }
        catch
        {
            ExitCode = 1064;
            // Do not report a clean stop while native work is still outstanding.
            Environment.Exit(3);
        }
    }
}
