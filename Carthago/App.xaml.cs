// File: App.xaml.cs
using System;
using System.Threading;
using System.Windows;
using Carthago.Services;
using DotNetEnv;

namespace Carthago
{
    public partial class App : Application
    {
        private CancellationTokenSource? _threatCts;

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
            _threatCts?.Cancel();
            base.OnExit(e);
        }
    }
}
