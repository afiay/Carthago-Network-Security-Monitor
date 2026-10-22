// SPDX-License-Identifier: MIT
// File: Models/AppPreferences.cs
using System;
using System.Collections.Generic;

namespace Carthago.Models
{
    /// <summary>
    /// Versioned app preferences persisted to %APPDATA%\Carthago\preferences.json.
    /// IMPORTANT: Property names are PascalCase because PreferencesService serializes with PropertyNamingPolicy = null.
    /// </summary>
    public partial class AppPreferences
    {
        public AppPreferences()
        {
        }

        public AppPreferences(AppPreferences other)
        {
            if (other is null) throw new ArgumentNullException(nameof(other));

            Version = other.Version;
            Sensitivity = other.Sensitivity;
             UpdatedUtc = other.UpdatedUtc;
             StartTime = other.StartTime;
             AutoStartCapture = other.AutoStartCapture;
             ShowAnomaliesOnly = other.ShowAnomaliesOnly;
             DefaultCaptureFilter = other.DefaultCaptureFilter;
             EnableWhois = other.EnableWhois;
             EnableReputation = other.EnableReputation;
            EnableOtlp = other.EnableOtlp;
            OtlpEndpoint = other.OtlpEndpoint;
            EnableAzure = other.EnableAzure;
            AzureDceUri = other.AzureDceUri;
            AzureDcrId = other.AzureDcrId;
            AzureStream = other.AzureStream;
            EnableCef = other.EnableCef;
            CefHost = other.CefHost;
            CefPort = other.CefPort;
            CefTls = other.CefTls;
            EnableSplunkHec = other.EnableSplunkHec;
            SplunkBaseUrl = other.SplunkBaseUrl;
            SplunkToken = other.SplunkToken;
            SplunkIndex = other.SplunkIndex;
            SplunkSource = other.SplunkSource;
            SplunkSourcetype = other.SplunkSourcetype;
            SplunkHost = other.SplunkHost;
            EnableElastic = other.EnableElastic;
            ElasticBaseUrl = other.ElasticBaseUrl;
            ElasticIndex = other.ElasticIndex;
            ElasticApiKey = other.ElasticApiKey;
            EnableKafka = other.EnableKafka;
            KafkaBootstrap = other.KafkaBootstrap;
            KafkaTopic = other.KafkaTopic;
            KafkaSaslUser = other.KafkaSaslUser;
            KafkaSaslPass = other.KafkaSaslPass;
            EnableFileSink = other.EnableFileSink;
            FileSinkDirectory = other.FileSinkDirectory;
            FileSinkMaxSizeMB = other.FileSinkMaxSizeMB;
            FileSinkRollDaily = other.FileSinkRollDaily;
            FileSinkCompressOnRotate = other.FileSinkCompressOnRotate;
            EnableWebhook = other.EnableWebhook;
            WebhookUrl = other.WebhookUrl;
            BlockedCountries = other.BlockedCountries is null
                ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                : new HashSet<string>(other.BlockedCountries, StringComparer.OrdinalIgnoreCase);
            EnableCountryBlocking = other.EnableCountryBlocking;
            CountryBlockApplyTo = other.CountryBlockApplyTo;
            Dashboard = other.Dashboard?.Clone() ?? new DashboardPreferences();
        }

        public AppPreferences Clone() => new(this);

        // ==== Core metadata ====
        public int Version { get; set; } = 4;

        /// <summary>Primary detection sensitivity (used by RuleEngine and UI).</summary>
        public Sensitivity Sensitivity { get; set; } = Sensitivity.Balanced;

        /// <summary>Informational timestamp of last update.</summary>
        public DateTime UpdatedUtc { get; set; } = DateTime.UtcNow;

        /// <summary>Application start (informational; some components read this for uptime/reporting).</summary>
        public DateTime StartTime { get; set; } = DateTime.UtcNow;

        // ==== Capture & enrichment (required by PreferencesService and other components) ====

         /// <summary>If true, start live capture automatically on app start.</summary>
         public bool AutoStartCapture { get; set; } = false;

         /// <summary>
         /// Default the main dashboard to incidents and anomalies instead of raw traffic telemetry.
         /// Raw views remain available from advanced navigation.
         /// </summary>
         public bool ShowAnomaliesOnly { get; set; } = true;

         /// <summary>Optional BPF-like filter string for the capture driver.</summary>
         public string? DefaultCaptureFilter { get; set; }

        /// <summary>Enable WHOIS/ASN/org resolution in enrichment pipeline.</summary>
        public bool EnableWhois { get; set; } = true;

        /// <summary>Enable reputation lookups (e.g., AbuseIPDB, threat feeds).</summary>
        public bool EnableReputation { get; set; } = true;

        // ==== Minimal Dashboard ====
        public DashboardPreferences Dashboard { get; set; } = new();

        // ==== OTLP Logs ====
        public bool EnableOtlp { get; set; } = false;
        /// <summary>e.g., http://localhost:4317 (gRPC) or http://collector:4318 (HTTP for logs if supported by your sink)</summary>
        public string? OtlpEndpoint { get; set; }

        // ==== Azure Monitor (DCE/DCR) ====
        public bool EnableAzure { get; set; } = false;
        public string? AzureDceUri { get; set; }
        public string? AzureDcrId { get; set; }
        public string? AzureStream { get; set; }

        // ==== CEF Syslog ====
        public bool EnableCef { get; set; } = false;
        public string? CefHost { get; set; }
        public int CefPort { get; set; } = 6514;
        public bool CefTls { get; set; } = true;

        // ==== Splunk HEC ====
        public bool EnableSplunkHec { get; set; } = false;
        public string? SplunkBaseUrl { get; set; }   // e.g., https://splunk.example.com:8088
        public string? SplunkToken { get; set; }
        public string? SplunkIndex { get; set; }
        public string? SplunkSource { get; set; }
        public string? SplunkSourcetype { get; set; }
        public string? SplunkHost { get; set; }

        // ==== Elastic (Bulk API) ====
        public bool EnableElastic { get; set; } = false;
        public string? ElasticBaseUrl { get; set; }  // e.g., http://elastic:9200
        public string? ElasticIndex { get; set; }    // e.g., carthago-detections-*
        public string? ElasticApiKey { get; set; }   // base64 "id:api_key"

        // ==== Kafka ====
        public bool EnableKafka { get; set; } = false;
        public string? KafkaBootstrap { get; set; }     // e.g., localhost:9092
        public string? KafkaTopic { get; set; }
        public string? KafkaSaslUser { get; set; }
        public string? KafkaSaslPass { get; set; }

        // ==== File JSONL Sink (durable local storage) ====
        public bool EnableFileSink { get; set; } = false;
        /// <summary>Directory for JSONL files. Null/empty -> %ProgramData%\Carthago\detections</summary>
        public string? FileSinkDirectory { get; set; }
        /// <summary>Max size per active file in MB before rotate</summary>
        public int FileSinkMaxSizeMB { get; set; } = 100;
        /// <summary>Start a fresh file when UTC day changes</summary>
        public bool FileSinkRollDaily { get; set; } = true;
        /// <summary>Compress rotated files (.gz)</summary>
        public bool FileSinkCompressOnRotate { get; set; } = true;

        // ==== Generic Webhook ====
        public bool EnableWebhook { get; set; } = false;
        public string? WebhookUrl { get; set; }
    }
}
