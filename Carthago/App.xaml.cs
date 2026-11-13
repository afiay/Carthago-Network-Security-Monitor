// File: App.xaml.cs
using System;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using Carthago.Contracts;
using Carthago.Services.Cli;
using System.Windows;
using Carthago.Services;
using DotNetEnv;

namespace Carthago
{
    public partial class App : Application
    {
        private CancellationTokenSource? _threatCts;
        private CancellationTokenSource? _cliCts;

        public App()
        {
            this.DispatcherUnhandledException += (s, e) =>
            {
                MessageBox.Show(e.Exception.ToString(), "Unhandled exception",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                e.Handled = true;
            };
        }

        protected override async void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Explicit opt-in. Never start a listener during ordinary WPF startup.
            if (e.Args.Contains("--enable-cli-ipc", StringComparer.Ordinal))
            {
                _cliCts = new CancellationTokenSource();
                var token = _cliCts.Token;
                _ = Task.Run(async () =>
                {
                    try { await WindowsLocalReadPipe.ServeLiveAsync(CliLiveQueryHost.QueryAsync, token); }
                    catch (OperationCanceledException) when (token.IsCancellationRequested) { }
                    catch (Exception ex) when (ex is not OutOfMemoryException)
                    {
                        Console.Error.WriteLine("[CLI] Local v2 query endpoint unavailable.");
                    }
                });
                _ = Task.Run(async () =>
                {
                    try { await WindowsLocalReadPipe.ServeAsync(CliReadHost.Query, token); }
                    catch (OperationCanceledException) when (token.IsCancellationRequested) { }
                    catch (Exception ex) when (ex is not OutOfMemoryException)
                    {
                        Console.Error.WriteLine("[CLI] Local read endpoint unavailable.");
                    }
                });
            }

            // Load .env
            try
            {
                Env.Load();
                var apiKey = Environment.GetEnvironmentVariable("ABUSEIPDB_API_KEY");
                if (string.IsNullOrWhiteSpace(apiKey))
                {
                    MessageBox.Show(
                        "⚠️ ABUSEIPDB_API_KEY not found. Reputation lookups will be disabled.",
                        "Configuration Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
                else
                {
                    Console.WriteLine("✅ .env loaded. ABUSEIPDB_API_KEY detected.");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to load .env file: {ex.Message}",
                    "Configuration Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }

            // Warm the bundled IANA service registry locally before packet capture.
            // This never performs network I/O; remote IANA updates are explicit only.
            try
            {
                await PortServiceResolver.InitializeAsync();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[PortServiceResolver] local init failed: {ex.Message}");
            }

            // Initialize threat feed (downloads to Data/ThreatIntel and refreshes in background)
            try
            {
                _threatCts = new CancellationTokenSource();
                await ThreatFeedService.InitializeAsync(_threatCts.Token);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ThreatFeed] init failed: {ex.Message}");
            }
        }

        protected override void OnExit(ExitEventArgs e)
        {
            _cliCts?.Cancel();
            _threatCts?.Cancel();
            base.OnExit(e);
        }
    }
}
