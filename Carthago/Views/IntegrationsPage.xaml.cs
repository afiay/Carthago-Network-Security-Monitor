// File: Views/IntegrationsPage.xaml.cs
// SPDX-License-Identifier: MIT
using System;
using System.Windows;
using System.Windows.Controls;
using Carthago.Models;
using Carthago.Sinks;
using Carthago.Services;
using Carthago.Telemetry; // <- OtelMetrics

namespace Carthago.Views
{
    public partial class IntegrationsPage : Page
    {
        private readonly SinkHost _sinkHost;
        private readonly EdrXdrViewModel _vm;

        public IntegrationsPage(SinkHost? sinkHost)
        {
            InitializeComponent();

            _sinkHost = sinkHost ?? throw new ArgumentNullException(nameof(sinkHost));
            _vm = new EdrXdrViewModel();
            DataContext = _vm;

            var prefs = PreferencesService.Current;
            ApplyPrefsToVm(prefs);
            SetPasswordBoxesFromPrefs(prefs);

            Unloaded += (_, __) =>
            {
                try { if (SplunkTokenBox != null) SplunkTokenBox.Password = string.Empty; } catch { }
                try { if (KafkaSaslPassBox != null) KafkaSaslPassBox.Password = string.Empty; } catch { }
            };
        }

        private void ApplyPrefsToVm(AppPreferences p)
        {
            // OTLP
            _vm.EnableOtlp = p.EnableOtlp;
            _vm.OtlpEndpoint = p.OtlpEndpoint;

            // Azure
            _vm.EnableAzure = p.EnableAzure;
            _vm.AzureDceUri = p.AzureDceUri;
            _vm.AzureDcrId = p.AzureDcrId;
            _vm.AzureStream = p.AzureStream;

            // CEF
            _vm.EnableCef = p.EnableCef;
            _vm.CefHost = p.CefHost;
            _vm.CefPort = p.CefPort;
            _vm.CefTls = p.CefTls;

            // Splunk
            _vm.EnableSplunkHec = p.EnableSplunkHec;
            _vm.SplunkBaseUrl = p.SplunkBaseUrl;
            _vm.SplunkIndex = p.SplunkIndex;
            _vm.SplunkSource = p.SplunkSource;
            _vm.SplunkSourcetype = p.SplunkSourcetype;
            _vm.SplunkHost = p.SplunkHost;

            // Elastic
            _vm.EnableElastic = p.EnableElastic;
            _vm.ElasticBaseUrl = p.ElasticBaseUrl;
            _vm.ElasticIndex = p.ElasticIndex;
            _vm.ElasticApiKey = p.ElasticApiKey;

            // Kafka
            _vm.EnableKafka = p.EnableKafka;
            _vm.KafkaBootstrap = p.KafkaBootstrap;
            _vm.KafkaTopic = p.KafkaTopic;
            _vm.KafkaSaslUser = p.KafkaSaslUser;

            // File sink
            _vm.EnableFileSink = p.EnableFileSink;
            _vm.FileSinkDirectory = p.FileSinkDirectory;
            _vm.FileSinkMaxSizeMB = p.FileSinkMaxSizeMB;
            _vm.FileSinkRollDaily = p.FileSinkRollDaily;
            _vm.FileSinkCompressOnRotate = p.FileSinkCompressOnRotate;

            // Webhook
            _vm.EnableWebhook = p.EnableWebhook;
            _vm.WebhookUrl = p.WebhookUrl;
        }

        private void SetPasswordBoxesFromPrefs(AppPreferences p)
        {
            try
            {
                if (SplunkTokenBox != null)
                    SplunkTokenBox.Password = string.IsNullOrWhiteSpace(p.SplunkToken) ? string.Empty : p.SplunkToken!;
            }
            catch { /* ignore */ }

            try
            {
                if (KafkaSaslPassBox != null)
                    KafkaSaslPassBox.Password = string.IsNullOrWhiteSpace(p.KafkaSaslPass) ? string.Empty : p.KafkaSaslPass!;
            }
            catch { /* ignore */ }
        }

        // --------------------------
        // Save helpers (per section)
        // --------------------------
        private static string? TrimOrNull(string? s) =>
            string.IsNullOrWhiteSpace(s) ? null : s!.Trim();

        private void SaveOtlp() => PreferencesService.Update(p =>
        {
            p.EnableOtlp = _vm.EnableOtlp;
            p.OtlpEndpoint = TrimOrNull(_vm.OtlpEndpoint);
            p.UpdatedUtc = DateTime.UtcNow;
        });

        private void SaveAzure() => PreferencesService.Update(p =>
        {
            p.EnableAzure = _vm.EnableAzure;
            p.AzureDceUri = TrimOrNull(_vm.AzureDceUri);
            p.AzureDcrId = TrimOrNull(_vm.AzureDcrId);
            p.AzureStream = TrimOrNull(_vm.AzureStream);
            p.UpdatedUtc = DateTime.UtcNow;
        });

        private void SaveCef() => PreferencesService.Update(p =>
        {
            p.EnableCef = _vm.EnableCef;
            p.CefHost = TrimOrNull(_vm.CefHost);
            p.CefPort = _vm.CefPort <= 0 ? 6514 : _vm.CefPort;
            p.CefTls = _vm.CefTls;
            p.UpdatedUtc = DateTime.UtcNow;
        });

        private void SaveSplunk() => PreferencesService.Update(p =>
        {
            p.EnableSplunkHec = _vm.EnableSplunkHec;
            p.SplunkBaseUrl = TrimOrNull(_vm.SplunkBaseUrl);
            p.SplunkIndex = TrimOrNull(_vm.SplunkIndex);
            p.SplunkSource = TrimOrNull(_vm.SplunkSource);
            p.SplunkSourcetype = TrimOrNull(_vm.SplunkSourcetype);
            p.SplunkHost = TrimOrNull(_vm.SplunkHost);

            if (SplunkTokenBox != null)
            {
                var tok = SplunkTokenBox.Password;
                p.SplunkToken = string.IsNullOrWhiteSpace(tok) ? null : tok;
            }
            p.UpdatedUtc = DateTime.UtcNow;
        });

        private void SaveElastic() => PreferencesService.Update(p =>
        {
            p.EnableElastic = _vm.EnableElastic;
            p.ElasticBaseUrl = TrimOrNull(_vm.ElasticBaseUrl);
            p.ElasticIndex = TrimOrNull(_vm.ElasticIndex);
            p.ElasticApiKey = TrimOrNull(_vm.ElasticApiKey);
            p.UpdatedUtc = DateTime.UtcNow;
        });

        private void SaveKafka() => PreferencesService.Update(p =>
        {
            p.EnableKafka = _vm.EnableKafka;
            p.KafkaBootstrap = TrimOrNull(_vm.KafkaBootstrap);
            p.KafkaTopic = TrimOrNull(_vm.KafkaTopic);
            p.KafkaSaslUser = TrimOrNull(_vm.KafkaSaslUser);

            if (KafkaSaslPassBox != null)
            {
                var pass = KafkaSaslPassBox.Password;
                p.KafkaSaslPass = string.IsNullOrWhiteSpace(pass) ? null : pass;
            }
            p.UpdatedUtc = DateTime.UtcNow;
        });

        private void SaveFileSink() => PreferencesService.Update(p =>
        {
            p.EnableFileSink = _vm.EnableFileSink;
            p.FileSinkDirectory = TrimOrNull(_vm.FileSinkDirectory);
            p.FileSinkMaxSizeMB = _vm.FileSinkMaxSizeMB <= 0 ? 100 : _vm.FileSinkMaxSizeMB;
            p.FileSinkRollDaily = _vm.FileSinkRollDaily;
            p.FileSinkCompressOnRotate = _vm.FileSinkCompressOnRotate;
            p.UpdatedUtc = DateTime.UtcNow;
        });

        private void SaveWebhook() => PreferencesService.Update(p =>
        {
            p.EnableWebhook = _vm.EnableWebhook;
            p.WebhookUrl = TrimOrNull(_vm.WebhookUrl);
            p.UpdatedUtc = DateTime.UtcNow;
        });

        // --------------------------
        // Click handlers (per tab)
        // --------------------------
        private static void Info(string msg) =>
            MessageBox.Show(msg, "Integrations", MessageBoxButton.OK, MessageBoxImage.Information);

        private static void Error(string msg) =>
            MessageBox.Show("Save failed: " + msg, "Integrations", MessageBoxButton.OK, MessageBoxImage.Error);

        private void Otlp_Save_Click(object s, RoutedEventArgs e)
        {
            try { SaveOtlp(); OtelMetrics.ReconfigureFromPreferences(); Info("OTLP settings saved."); }
            catch (Exception ex) { Error(ex.Message); }
        }

        private void Otlp_Reload_Click(object s, RoutedEventArgs e)
        {
            Otlp_Save_Click(s, e);
            _sinkHost.Reload();
            try { OtelMetrics.EmitTestMetric(); } catch { }
        }

        // Satisfies Click="Otlp_Test_Click" in XAML (if present)
        private void Otlp_Test_Click(object s, RoutedEventArgs e)
        {
            try
            {
                OtelMetrics.EmitTestMetric();
                Info("Sent a one-off test metric (counter=1).");
            }
            catch (Exception ex)
            {
                Error("Failed to send test metric: " + ex.Message);
            }
        }

        private void Azure_Save_Click(object s, RoutedEventArgs e)
        {
            try { SaveAzure(); Info("Azure settings saved."); }
            catch (Exception ex) { Error(ex.Message); }
        }

        private void Azure_Reload_Click(object s, RoutedEventArgs e)
        {
            Azure_Save_Click(s, e);
            _sinkHost.Reload();
        }

        private void Cef_Save_Click(object s, RoutedEventArgs e)
        {
            try { SaveCef(); Info("CEF settings saved."); }
            catch (Exception ex) { Error(ex.Message); }
        }

        private void Cef_Reload_Click(object s, RoutedEventArgs e)
        {
            Cef_Save_Click(s, e);
            _sinkHost.Reload();
        }

        private void Splunk_Save_Click(object s, RoutedEventArgs e)
        {
            try { SaveSplunk(); Info("Splunk settings saved."); }
            catch (Exception ex) { Error(ex.Message); }
        }

        private void Splunk_Reload_Click(object s, RoutedEventArgs e)
        {
            Splunk_Save_Click(s, e);
            _sinkHost.Reload();
        }

        private void Elastic_Save_Click(object s, RoutedEventArgs e)
        {
            try { SaveElastic(); Info("Elastic settings saved."); }
            catch (Exception ex) { Error(ex.Message); }
        }

        private void Elastic_Reload_Click(object s, RoutedEventArgs e)
        {
            Elastic_Save_Click(s, e);
            _sinkHost.Reload();
        }

        private void Kafka_Save_Click(object s, RoutedEventArgs e)
        {
            try { SaveKafka(); Info("Kafka settings saved."); }
            catch (Exception ex) { Error(ex.Message); }
        }

        private void Kafka_Reload_Click(object s, RoutedEventArgs e)
        {
            Kafka_Save_Click(s, e);
            _sinkHost.Reload();
        }

        private void File_Save_Click(object s, RoutedEventArgs e)
        {
            try { SaveFileSink(); Info("File sink settings saved."); }
            catch (Exception ex) { Error(ex.Message); }
        }

        private void File_Reload_Click(object s, RoutedEventArgs e)
        {
            File_Save_Click(s, e);
            _sinkHost.Reload();
        }

        private void Webhook_Save_Click(object s, RoutedEventArgs e)
        {
            try { SaveWebhook(); Info("Webhook settings saved."); }
            catch (Exception ex) { Error(ex.Message); }
        }

        private void Webhook_Reload_Click(object s, RoutedEventArgs e)
        {
            Webhook_Save_Click(s, e);
            _sinkHost.Reload();
        }
    }

    // Minimal POCO VM for bindings
    public sealed class EdrXdrViewModel
    {
        // OTLP
        public bool EnableOtlp { get; set; }
        public string? OtlpEndpoint { get; set; }

        // Azure
        public bool EnableAzure { get; set; }
        public string? AzureDceUri { get; set; }
        public string? AzureDcrId { get; set; }
        public string? AzureStream { get; set; }

        // CEF
        public bool EnableCef { get; set; }
        public string? CefHost { get; set; }
        public int CefPort { get; set; } = 6514;
        public bool CefTls { get; set; } = true;

        // Splunk
        public bool EnableSplunkHec { get; set; }
        public string? SplunkBaseUrl { get; set; }
        public string? SplunkIndex { get; set; }
        public string? SplunkSource { get; set; }
        public string? SplunkSourcetype { get; set; }
        public string? SplunkHost { get; set; }

        // Elastic
        public bool EnableElastic { get; set; }
        public string? ElasticBaseUrl { get; set; }
        public string? ElasticIndex { get; set; }
        public string? ElasticApiKey { get; set; }

        // Kafka
        public bool EnableKafka { get; set; }
        public string? KafkaBootstrap { get; set; }
        public string? KafkaTopic { get; set; }
        public string? KafkaSaslUser { get; set; }

        // File JSONL Sink
        public bool EnableFileSink { get; set; }
        public string? FileSinkDirectory { get; set; }
        public int FileSinkMaxSizeMB { get; set; } = 100;
        public bool FileSinkRollDaily { get; set; } = true;
        public bool FileSinkCompressOnRotate { get; set; } = true;

        // Webhook
        public bool EnableWebhook { get; set; }
        public string? WebhookUrl { get; set; }
    }
}
