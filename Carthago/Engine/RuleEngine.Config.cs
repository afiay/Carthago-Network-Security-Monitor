// SPDX-License-Identifier: MIT
// File: Engine/RuleEngine.Config.cs
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Profiles;
using Carthago.Engine.Rules.Tuning;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Services
{
    /// <summary>
    /// Defaults and configuration: thresholds, toggles, hot-reload watcher.
    /// NOTE:
    /// - Keep ALL defaults, _cfg, _json, LoadConfig, StartConfigWatcher here to avoid duplicate symbols.
    /// - Other partials (Core/Detectors) must NOT redeclare these.
    /// </summary>
    public static partial class RuleEngine
    {
        // ===== Defaults (overridable via rules.json) =====
        private const int PortScanThreshold = 5;
        private const int PortScanWindowSeconds = 30;

        private const int FloodThreshold = 5;
        private const int FloodWindowSeconds = 10;
        private const int FloodByteThreshold = 1_000_000; // 1MB
        private const double SynAckRatioThreshold = 5.0;

        private const int BruteForceThreshold = 10;
        private const int BruteForceWindowSeconds = 60;

        private const int DnsThreshold = 20;
        private const int DnsWindowSeconds = 30;
        private const double DnsEntropyThreshold = 3.5;
        private const double DnsAvgLabelLenThreshold = 20.0;
        private const int DnsQueryLenThreshold = 50;

        private const int BeaconMinSamples = 5;
        private const int BeaconMinObservationSeconds = 30;
        private const double BeaconStdDevFraction = 0.05; // 5%
        private const int BeaconAutocorrLags = 3;

        private const int ExfilThresholdBytes = 5_000_000; // 5 MB
        private const int ExfilWindowSeconds = 60;

        private const int DhcpThreshold = 20;
        private const int DhcpWindowSeconds = 60;

        private const int AlertCooldownSecondsDefault = 60;

        private const int StateTtlMinutes = 30;
        private const int CleanupIntervalSeconds = 120;
        private static DateTime _lastCleanup;

        // ---- New defaults for R017–R022 ----
        private const int HostSweepWindowSeconds = 30;          // R017
        private const int HostSweepDistinctHostsThreshold = 10; // R017

        private const int HttpUriLenThreshold = 2000;           // R019
        private const int HttpUriChunkLenThreshold = 80;        // R019
        private const double HttpUriEntropyThreshold = 4.0;     // R019

        private const int IcmpWindowSeconds = 60;               // R021
        private const int IcmpPktCountThreshold = 20;           // R021
        private const int IcmpTotalBytesThreshold = 100_000;    // R021

        private const int DnsNxWindowSeconds = 60;              // R022
        private const int DnsNxThreshold = 30;                  // R022

        // ---- New default for enhanced R013 ----
        internal const double UncommonPortsAnomalyThresholdDefault = 0.66;

        // ===== Logging (used by Core.LogDetection) =====
        private static readonly JsonSerializerOptions _json = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = false
        };

        // Options for file deserialization: tolerate comments/trailing commas and numbers-as-strings.
        private static readonly JsonSerializerOptions _fileJsonOptions = new()
        {
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
            NumberHandling = JsonNumberHandling.AllowReadingFromString,
            PropertyNameCaseInsensitive = true
        };

        private const string EnvPrefix = "CARTHAGO_RULES__";
        private static string? _lastCfgHash;

        // ===== Config (rules.json) =====
        // Intentionally private; access via _cfg inside RuleEngine.
        // Supports both the legacy flat rules.json shape and the safer v2 shape:
        // { "Version": 2, "Profile": "Balanced", "Global": {...}, "Rules": { "R001": { "Enabled": true } } }
        private sealed class RuleCfgGlobal
        {
            public int? AlertCooldownSeconds { get; set; }
        }

        private sealed class RuleCfgRule
        {
            public bool? Enabled { get; set; }
            public int? Threshold { get; set; }
            public int? WindowSeconds { get; set; }
            public string? Mode { get; set; }

            [JsonExtensionData]
            public Dictionary<string, JsonElement>? ExtensionData { get; set; }
        }

        private class RuleCfg
        {
            public int? Version { get; set; }
            public string? Profile { get; set; }
            public RuleCfgGlobal? Global { get; set; }
            public Dictionary<string, RuleCfgRule>? Rules { get; set; }

            [JsonExtensionData]
            public Dictionary<string, JsonElement>? ExtensionData { get; set; }

            public bool? EnablePortScan { get; set; }
            public int? PortScanThreshold { get; set; }
            public int? PortScanWindowSeconds { get; set; }

            public bool? EnableFlood { get; set; }
            public int? FloodThreshold { get; set; }
            public int? FloodWindowSeconds { get; set; }
            public int? FloodByteThreshold { get; set; }
            public double? SynAckRatioThreshold { get; set; }

            public bool? EnableThreatFeed { get; set; }

            public bool? EnableBruteForce { get; set; }
            public int? BruteForceThreshold { get; set; }
            public int? BruteForceWindowSeconds { get; set; }

            public bool? EnableSuspiciousProtocol { get; set; }

            public bool? EnableDns { get; set; }
            public int? DnsThreshold { get; set; }
            public int? DnsWindowSeconds { get; set; }
            public double? DnsEntropyThreshold { get; set; }
            public double? DnsAvgLabelLenThreshold { get; set; }
            public int? DnsQueryLenThreshold { get; set; }

            public bool? EnableBeaconing { get; set; }
            public int? BeaconMinSamples { get; set; }
            public int? BeaconMinObservationSeconds { get; set; }
            public double? BeaconStdDevFraction { get; set; }
            public int? BeaconAutocorrLags { get; set; }

            public bool? EnableExfiltration { get; set; }
            public int? ExfilThresholdBytes { get; set; }
            public int? ExfilWindowSeconds { get; set; }

            public bool? EnableVpnProxy { get; set; }

            public bool? EnableGeoip { get; set; }
            public List<string>? GeoipBlacklist { get; set; }

            public bool? EnableDhcp { get; set; }
            public int? DhcpThreshold { get; set; }
            public int? DhcpWindowSeconds { get; set; }

            public bool? EnableTlsInspection { get; set; }
            public bool? EnableUncommonPorts { get; set; }
            public bool? EnableCleartextCredentials { get; set; }
            public bool? EnableArpSpoofing { get; set; }
            public bool? EnableReputation { get; set; }

            public int? AlertCooldownSeconds { get; set; }
            public int? StateTtlMinutes { get; set; }
            public int? CleanupIntervalSeconds { get; set; }

            // ---- R017–R022 ----
            public bool? EnableHostSweep { get; set; }           // R017
            public int? HostSweepWindowSeconds { get; set; }
            public int? HostSweepDistinctHostsThreshold { get; set; }

            public bool? EnableHttpIpNoHost { get; set; }        // R018

            public bool? EnableHttpUriAnomaly { get; set; }      // R019
            public int? HttpUriLenThreshold { get; set; }
            public int? HttpUriChunkLenThreshold { get; set; }
            public double? HttpUriEntropyThreshold { get; set; }

            public bool? EnableSmtpEgress25 { get; set; }        // R020
            public List<string>? SmtpAllowedSources { get; set; }

            public bool? EnableIcmpTunnel { get; set; }          // R021
            public int? IcmpWindowSeconds { get; set; }
            public int? IcmpPktCountThreshold { get; set; }
            public int? IcmpTotalBytesThreshold { get; set; }

            public bool? EnableDnsNxDomainSpike { get; set; }    // R022
            public int? DnsNxWindowSeconds { get; set; }
            public int? DnsNxThreshold { get; set; }

            // ---- Enhanced R013 ----
            public double? UncommonPortsAnomalyThreshold { get; set; }

            // ---- R023–R036 toggles ----
            public bool? EnableTlsNoSniToIp { get; set; }          // R023
            public bool? EnableRareTlsFingerprint { get; set; }    // R024
            public bool? EnableTlsCertExpiry { get; set; }         // R025
            public bool? EnableSmbToInternet { get; set; }         // R026
            public bool? EnableAdminEgress { get; set; }           // R027
            public bool? EnableExternalDnsDirect { get; set; }     // R028
            public bool? EnableQuicAnomaly { get; set; }           // R029
            public bool? EnableAdminLateralSweep { get; set; }     // R030
            public bool? EnableDnsTxtSpike { get; set; }           // R031
            public bool? EnableSuspiciousUserAgent { get; set; }   // R032
            public bool? EnableIcmpOversized { get; set; }         // R033
            public bool? EnableDoH { get; set; }                   // R034
            public bool? EnableRareSshFingerprint { get; set; }    // R035
            public bool? EnablePairExfiltration { get; set; }      // R036

            // ---- Strategy detectors (R037–R039) ----
            public bool? EnableJa4DriftPerSni { get; set; }          // R037
            public bool? EnableEncryptedDnsBootstrap { get; set; }   // R038
            public bool? EnableAsnNoveltySensitive { get; set; }     // R039

            // ---- Extended strategy / HTTP/TLS heuristics (R040–R049) ----
            public bool? EnableEncryptedLowAndSlow { get; set; }       // R040
            public bool? EnableJa4FanoutSweep { get; set; }            // R041
            public bool? EnableUncommonQuicAlpn { get; set; }          // R042
            public bool? EnableSniHostMismatch { get; set; }           // R043
            public bool? EnableHttpMethodAnomaly { get; set; }         // R044
            public bool? EnableSparseHttpPost { get; set; }            // R045
            public bool? EnableUnauthorizedVpnEgress { get; set; }     // R046
            public bool? EnableHttpBasicAuthToIp { get; set; }         // R047
            public bool? EnableAlternateDoHPatterns { get; set; }      // R048
            public bool? EnableSuspiciousSniShape { get; set; }        // R049

            // Optional: global pack switch (lets you disable the advanced set at once)
            public bool? EnableAdvancedHeuristics { get; set; }
        }

        private static RuleCfg _cfg = new();

        // Config hot-reload support
        private static readonly object _cfgLock = new();
        private static FileSystemWatcher? _cfgWatcher;
        private static string _cfgPath = "rules.json";
        private static long _cfgLastReloadTicks; // debounce

        static RuleEngine()
        {
            LoadConfig();
            ApprovedAssetRegistry.Load();
            StartConfigWatcher(_cfgPath);
            _lastCleanup = DateTime.UtcNow;
        }

        /// <summary>Loads configuration from the given path (defaults to "rules.json"), merges env overrides, validates, and applies.</summary>
        public static void LoadConfig(string path = "rules.json")
        {
            try
            {
                lock (_cfgLock)
                {
                    var resolvedPath = ResolveConfigPath(path);
                    _cfgPath = resolvedPath;
                    string? json = null;

                    if (!File.Exists(resolvedPath))
                    {
                        Console.WriteLine("[RuleEngine] rules.json not found; using defaults.");
                        if (Environment.GetEnvironmentVariable("CARTHAGO_RULES_WRITE_TEMPLATE") == "1")
                        {
                            TryWriteTemplate(resolvedPath);
                        }
                    }
                    else
                    {
                        json = TryReadAllTextWithRetries(resolvedPath, maxAttempts: 3, sleepMs: 60);
                        if (json == null)
                        {
                            Console.Error.WriteLine("[RuleEngine] Failed to read rules.json; keeping previous config.");
                            return;
                        }

                        // Skip reloads that are content-identical
                        var hash = Sha256(json);
                        if (hash == _lastCfgHash)
                        {
                            _cfgLastReloadTicks = DateTime.UtcNow.Ticks;
                            return;
                        }

                        var cfgFromFile = Deserialize(json);
                        if (cfgFromFile == null)
                        {
                            RuleEngineHealthState.ReportConfigReloadFailure("rules.json parse failed; keeping previous active config");
                            return;
                        }

                        var previousProfile = string.IsNullOrWhiteSpace(_cfg.Profile)
                            ? RuleTuningCatalog.DefaultProfileName
                            : _cfg.Profile!;
                        if (!string.IsNullOrWhiteSpace(cfgFromFile.Profile) && !RuleTuningCatalog.IsKnownProfile(cfgFromFile.Profile))
                        {
                            RuleEngineHealthState.ReportConfigReloadFailure($"Unknown rule profile '{cfgFromFile.Profile}'; keeping previous active profile '{previousProfile}'.");
                            cfgFromFile.Profile = previousProfile;
                        }
                        else if (string.IsNullOrWhiteSpace(cfgFromFile.Profile))
                        {
                            cfgFromFile.Profile = previousProfile;
                        }

                        _cfg = cfgFromFile;
                        _lastCfgHash = hash;
                        Console.WriteLine($"[RuleEngine] Config loaded from {resolvedPath}");
                    }

                    // Apply environment overrides after file
                    ApplyEnvOverrides(_cfg);

                    // Normalize/Clamp to safe ranges
                    Normalize(_cfg);
                    _cfg.Profile = RuleTuningCatalog.NormalizeProfileName(_cfg.Profile);

                    // Merge GeoIP blacklist into runtime set if provided
                    if (_cfg.GeoipBlacklist != null && _cfg.GeoipBlacklist.Count > 0)
                        _blacklistedCountries = new HashSet<string>(_cfg.GeoipBlacklist, StringComparer.OrdinalIgnoreCase);

                    _cfgLastReloadTicks = DateTime.UtcNow.Ticks;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RuleEngine] LoadConfig failed: {ex}");
                RuleEngineHealthState.ReportConfigReloadFailure(ex.Message);
            }
        }

        private static string ResolveConfigPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                path = "rules.json";

            if (Path.IsPathRooted(path) || File.Exists(path))
                return path;

            var candidates = new[]
            {
                path,
                Path.Combine(Environment.CurrentDirectory, path),
                Path.Combine(Environment.CurrentDirectory, "Carthago", path),
                Path.Combine(AppContext.BaseDirectory, path),
                Path.Combine(AppContext.BaseDirectory, "Carthago", path)
            };

            foreach (var candidate in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (File.Exists(candidate))
                    return candidate;
            }

            return path;
        }


        private static bool? TryGetRuleEnabledOverride(string ruleId)
        {
            if (string.IsNullOrWhiteSpace(ruleId) || _cfg.Rules == null) return null;
            if (_cfg.Rules.TryGetValue(ruleId, out var rule) && rule?.Enabled != null) return rule.Enabled;

            foreach (var kv in _cfg.Rules)
            {
                if (string.Equals(kv.Key, ruleId, StringComparison.OrdinalIgnoreCase))
                    return kv.Value?.Enabled;
            }

            return null;
        }

        private static RuleMode? TryGetRuleModeOverride(string ruleId)
        {
            if (string.IsNullOrWhiteSpace(ruleId) || _cfg.Rules == null) return null;
            RuleCfgRule? rule = null;
            if (!_cfg.Rules.TryGetValue(ruleId, out rule))
            {
                foreach (var kv in _cfg.Rules)
                {
                    if (string.Equals(kv.Key, ruleId, StringComparison.OrdinalIgnoreCase))
                    {
                        rule = kv.Value;
                        break;
                    }
                }
            }

            if (string.IsNullOrWhiteSpace(rule?.Mode)) return null;
            return Enum.TryParse<RuleMode>(rule.Mode, ignoreCase: true, out var mode) ? mode : null;
        }

        public static RuleMode GetRuleMode(string ruleId, bool defaultEnabled)
        {
            var enabledOverride = TryGetRuleEnabledOverride(ruleId);
            if (enabledOverride == false) return RuleMode.Disabled;

            var explicitMode = TryGetRuleModeOverride(ruleId);
            if (explicitMode.HasValue) return explicitMode.Value;

            var profileMode = RuleProfileApplier.ResolveMode(_cfg.Profile, ruleId, defaultEnabled ? RuleMode.Alert : RuleMode.Disabled);
            if (profileMode == RuleMode.Disabled) return RuleMode.Disabled;

            var legacyEnabled = IsRuleEnabledById(ruleId, defaultEnabled);
            return legacyEnabled ? profileMode : RuleMode.Disabled;
        }

        private static int? TryGetRuleThresholdOverride(string ruleId)
        {
            if (string.IsNullOrWhiteSpace(ruleId) || _cfg.Rules == null) return null;
            if (_cfg.Rules.TryGetValue(ruleId, out var rule) && rule?.Threshold != null) return rule.Threshold;
            foreach (var kv in _cfg.Rules)
            {
                if (string.Equals(kv.Key, ruleId, StringComparison.OrdinalIgnoreCase))
                    return kv.Value?.Threshold;
            }
            return null;
        }

        private static int? TryGetRuleWindowSecondsOverride(string ruleId)
        {
            if (string.IsNullOrWhiteSpace(ruleId) || _cfg.Rules == null) return null;
            if (_cfg.Rules.TryGetValue(ruleId, out var rule) && rule?.WindowSeconds != null) return rule.WindowSeconds;
            foreach (var kv in _cfg.Rules)
            {
                if (string.Equals(kv.Key, ruleId, StringComparison.OrdinalIgnoreCase))
                    return kv.Value?.WindowSeconds;
            }
            return null;
        }

        public static int GetRuleIntSetting(string ruleId, string settingName, int defaultValue, int min = 1, int max = int.MaxValue)
        {
            if (string.IsNullOrWhiteSpace(ruleId) || string.IsNullOrWhiteSpace(settingName))
                return defaultValue;

            int? value = null;
            if (string.Equals(settingName, "Threshold", StringComparison.OrdinalIgnoreCase))
                value = TryGetRuleThresholdOverride(ruleId);
            else if (string.Equals(settingName, "WindowSeconds", StringComparison.OrdinalIgnoreCase))
                value = TryGetRuleWindowSecondsOverride(ruleId);
            else
                value = TryGetRuleExtensionInt(ruleId, settingName);

            if (!value.HasValue) return defaultValue;
            return Math.Clamp(value.Value, min, max);
        }

        public static double GetRuleDoubleSetting(string ruleId, string settingName, double defaultValue, double min = 0.0, double max = double.MaxValue)
        {
            var value = TryGetRuleExtensionDouble(ruleId, settingName);
            if (!value.HasValue || !double.IsFinite(value.Value)) return defaultValue;
            return Math.Clamp(value.Value, min, max);
        }

        public static IReadOnlyList<string> GetRuleStringListSetting(string ruleId, string settingName)
        {
            var element = TryGetRuleExtensionElement(ruleId, settingName);
            if (element == null) return Array.Empty<string>();

            try
            {
                if (element.Value.ValueKind == JsonValueKind.Array)
                {
                    return element.Value.EnumerateArray()
                        .Select(x => x.GetString())
                        .Where(x => !string.IsNullOrWhiteSpace(x))
                        .Select(x => x!.Trim())
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToArray();
                }

                if (element.Value.ValueKind == JsonValueKind.String)
                {
                    return element.Value.GetString()?
                        .Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(x => x.Trim())
                        .Where(x => x.Length > 0)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToArray() ?? Array.Empty<string>();
                }
            }
            catch { }

            return Array.Empty<string>();
        }

        private static int? TryGetRuleExtensionInt(string ruleId, string settingName)
        {
            var element = TryGetRuleExtensionElement(ruleId, settingName);
            if (element == null) return null;
            try
            {
                if (element.Value.ValueKind == JsonValueKind.Number && element.Value.TryGetInt32(out var n)) return n;
                if (element.Value.ValueKind == JsonValueKind.String && int.TryParse(element.Value.GetString(), out var s)) return s;
            }
            catch { }
            return null;
        }

        private static double? TryGetRuleExtensionDouble(string ruleId, string settingName)
        {
            var element = TryGetRuleExtensionElement(ruleId, settingName);
            if (element == null) return null;
            try
            {
                if (element.Value.ValueKind == JsonValueKind.Number && element.Value.TryGetDouble(out var n)) return n;
                if (element.Value.ValueKind == JsonValueKind.String &&
                    double.TryParse(element.Value.GetString(), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var s))
                    return s;
            }
            catch { }
            return null;
        }

        private static JsonElement? TryGetRuleExtensionElement(string ruleId, string settingName)
        {
            if (_cfg.Rules == null) return null;
            if (!_cfg.Rules.TryGetValue(ruleId, out var rule) || rule == null)
            {
                foreach (var kv in _cfg.Rules)
                {
                    if (string.Equals(kv.Key, ruleId, StringComparison.OrdinalIgnoreCase))
                    {
                        rule = kv.Value;
                        break;
                    }
                }
            }

            if (rule?.ExtensionData == null) return null;
            foreach (var kv in rule.ExtensionData)
            {
                if (string.Equals(kv.Key, settingName, StringComparison.OrdinalIgnoreCase))
                    return kv.Value;
            }

            return null;
        }

        private static void StartConfigWatcher(string path)
        {
            try
            {
                var full = Path.GetFullPath(path);
                var dir = Path.GetDirectoryName(full) ?? Environment.CurrentDirectory;
                var file = Path.GetFileName(full);

                _cfgWatcher?.Dispose();
                _cfgWatcher = new FileSystemWatcher(dir)
                {
                    Filter = file,
                    EnableRaisingEvents = true,
                    IncludeSubdirectories = false,
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size
                };

                FileSystemEventHandler onChange = (_, __) =>
                {
                    var nowTicks = DateTime.UtcNow.Ticks;
                    var last = System.Threading.Interlocked.Read(ref _cfgLastReloadTicks);
                    if (new TimeSpan(nowTicks - last).TotalMilliseconds < 250) return; // debounce rapid write bursts
                    LoadConfig(_cfgPath);
                };

                _cfgWatcher.Changed += onChange;
                _cfgWatcher.Created += onChange;
                _cfgWatcher.Deleted += onChange;
                _cfgWatcher.Renamed += (_, __) => LoadConfig(_cfgPath);
                _cfgWatcher.Error += (_, e) => Console.Error.WriteLine($"[RuleEngine] Config watcher error: {e.GetException()}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RuleEngine] StartConfigWatcher failed: {ex}");
            }
        }

        // ===== Helpers: file IO, JSON, hashing, env overrides, validation =====

        private static string? TryReadAllTextWithRetries(string path, int maxAttempts, int sleepMs)
        {
            for (int i = 0; i < maxAttempts; i++)
            {
                try
                {
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                    return sr.ReadToEnd();
                }
                catch (IOException)
                {
                    System.Threading.Thread.Sleep(sleepMs);
                }
                catch (UnauthorizedAccessException)
                {
                    System.Threading.Thread.Sleep(sleepMs);
                }
            }
            return null;
        }

        private static RuleCfg? Deserialize(string json)
        {
            try
            {
                return JsonSerializer.Deserialize<RuleCfg>(json, _fileJsonOptions) ?? new RuleCfg();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RuleEngine] rules.json parse error: {ex.Message}");
                RuleEngineHealthState.ReportConfigReloadFailure(ex.Message);
                return null; // keep previous active config
            }
        }

        private static string Sha256(string s)
        {
            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(s));
            return Convert.ToHexString(hash);
        }

        /// <summary>
        /// Applies environment overrides with prefix CARTHAGO_RULES__.
        /// Example:
        ///   CARTHAGO_RULES__DnsThreshold=40
        ///   CARTHAGO_RULES__SmtpAllowedSources=10.0.0.10,10.0.0.11
        ///   CARTHAGO_RULES__EnableQuicAnomaly=false
        /// </summary>
        private static void ApplyEnvOverrides(RuleCfg cfg)
        {
            try
            {
                IDictionary env = Environment.GetEnvironmentVariables();
                if (env.Count == 0) return;

                foreach (DictionaryEntry de in env)
                {
                    var key = de.Key?.ToString();
                    if (string.IsNullOrEmpty(key) || !key.StartsWith(EnvPrefix, StringComparison.Ordinal)) continue;

                    var propName = key.Substring(EnvPrefix.Length);
                    var prop = typeof(RuleCfg).GetProperties()
                        .FirstOrDefault(p => string.Equals(p.Name, propName, StringComparison.OrdinalIgnoreCase));
                    if (prop == null) continue;

                    string raw = de.Value?.ToString() ?? string.Empty;

                    try
                    {
                        object? value = null;

                        if (prop.PropertyType == typeof(int?))
                        {
                            if (int.TryParse(raw, out var v)) value = v;
                        }
                        else if (prop.PropertyType == typeof(double?))
                        {
                            if (double.TryParse(raw, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var v)) value = v;
                        }
                        else if (prop.PropertyType == typeof(bool?))
                        {
                            if (bool.TryParse(raw, out var v)) value = v;
                        }
                        else if (prop.PropertyType == typeof(List<string>))
                        {
                            var list = raw.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries)
                                          .Select(x => x.Trim())
                                          .Where(x => x.Length > 0)
                                          .ToList();
                            value = list.Count > 0 ? list : null;
                        }
                        else if (prop.PropertyType == typeof(string))
                        {
                            value = string.IsNullOrWhiteSpace(raw) ? null : raw.Trim();
                        }

                        if (value != null)
                        {
                            prop.SetValue(cfg, value);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"[RuleEngine] Env override {key} failed: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RuleEngine] ApplyEnvOverrides error: {ex.Message}");
            }
        }

        /// <summary>Clamp/null-fix misconfigurations to safe, non-noisy ranges.</summary>
        private static void Normalize(RuleCfg c)
        {
            // helper local funcs
            static int? PosIntOrNull(int? v, int fallbackMin = 1) =>
                (v.HasValue && v.Value >= fallbackMin) ? v : null;

            static double? PosDoubleOrNull(double? v, double min = 0.0001) =>
                (v.HasValue && v.Value >= min && double.IsFinite(v.Value)) ? v : null;

            if (c.Global?.AlertCooldownSeconds != null)
                c.AlertCooldownSeconds = c.Global.AlertCooldownSeconds;

            if (c.Rules != null)
            {
                var normalizedRules = new Dictionary<string, RuleCfgRule>(StringComparer.OrdinalIgnoreCase);
                foreach (var kv in c.Rules)
                {
                    if (string.IsNullOrWhiteSpace(kv.Key) || kv.Value == null) continue;
                    var id = kv.Key.Trim().ToUpperInvariant();
                    kv.Value.Threshold = PosIntOrNull(kv.Value.Threshold);
                    kv.Value.WindowSeconds = PosIntOrNull(kv.Value.WindowSeconds);
                    if (!string.IsNullOrWhiteSpace(kv.Value.Mode) && !Enum.TryParse<RuleMode>(kv.Value.Mode, ignoreCase: true, out _))
                        kv.Value.Mode = null;
                    normalizedRules[id] = kv.Value;
                }
                c.Rules = normalizedRules;
            }

            // Windows/thresholds
            c.PortScanThreshold = PosIntOrNull(c.PortScanThreshold);
            c.PortScanWindowSeconds = PosIntOrNull(c.PortScanWindowSeconds);

            c.FloodThreshold = PosIntOrNull(c.FloodThreshold);
            c.FloodWindowSeconds = PosIntOrNull(c.FloodWindowSeconds);
            c.FloodByteThreshold = PosIntOrNull(c.FloodByteThreshold, 1024);
            c.SynAckRatioThreshold = PosDoubleOrNull(c.SynAckRatioThreshold, 1.0);

            c.BruteForceThreshold = PosIntOrNull(c.BruteForceThreshold);
            c.BruteForceWindowSeconds = PosIntOrNull(c.BruteForceWindowSeconds);

            c.DnsThreshold = PosIntOrNull(c.DnsThreshold);
            c.DnsWindowSeconds = PosIntOrNull(c.DnsWindowSeconds);
            c.DnsEntropyThreshold = PosDoubleOrNull(c.DnsEntropyThreshold, 0.5);
            c.DnsAvgLabelLenThreshold = PosDoubleOrNull(c.DnsAvgLabelLenThreshold, 1.0);
            c.DnsQueryLenThreshold = PosIntOrNull(c.DnsQueryLenThreshold, 8);

            c.BeaconMinSamples = PosIntOrNull(c.BeaconMinSamples, 3);
            c.BeaconMinObservationSeconds = PosIntOrNull(c.BeaconMinObservationSeconds, 5);
            c.BeaconStdDevFraction = PosDoubleOrNull(c.BeaconStdDevFraction, 0.001);
            c.BeaconAutocorrLags = PosIntOrNull(c.BeaconAutocorrLags, 1);

            c.ExfilThresholdBytes = PosIntOrNull(c.ExfilThresholdBytes, 1024);
            c.ExfilWindowSeconds = PosIntOrNull(c.ExfilWindowSeconds);

            c.DhcpThreshold = PosIntOrNull(c.DhcpThreshold, 5);
            c.DhcpWindowSeconds = PosIntOrNull(c.DhcpWindowSeconds, 5);

            c.AlertCooldownSeconds = PosIntOrNull(c.AlertCooldownSeconds, 0); // allow 0 = no cooldown
            c.StateTtlMinutes = PosIntOrNull(c.StateTtlMinutes, 1);
            c.CleanupIntervalSeconds = PosIntOrNull(c.CleanupIntervalSeconds, 5);

            // R017–R022
            c.HostSweepWindowSeconds = PosIntOrNull(c.HostSweepWindowSeconds, 5);
            c.HostSweepDistinctHostsThreshold = PosIntOrNull(c.HostSweepDistinctHostsThreshold, 3);

            c.HttpUriLenThreshold = PosIntOrNull(c.HttpUriLenThreshold, 64);
            c.HttpUriChunkLenThreshold = PosIntOrNull(c.HttpUriChunkLenThreshold, 16);
            c.HttpUriEntropyThreshold = PosDoubleOrNull(c.HttpUriEntropyThreshold, 1.0);

            c.IcmpWindowSeconds = PosIntOrNull(c.IcmpWindowSeconds, 5);
            c.IcmpPktCountThreshold = PosIntOrNull(c.IcmpPktCountThreshold, 5);
            c.IcmpTotalBytesThreshold = PosIntOrNull(c.IcmpTotalBytesThreshold, 1024);

            c.DnsNxWindowSeconds = PosIntOrNull(c.DnsNxWindowSeconds, 5);
            c.DnsNxThreshold = PosIntOrNull(c.DnsNxThreshold, 3);

            // Enhanced R013
            if (c.UncommonPortsAnomalyThreshold.HasValue)
            {
                var v = c.UncommonPortsAnomalyThreshold.Value;
                if (!double.IsFinite(v) || v < 0.0 || v > 1.0)
                    c.UncommonPortsAnomalyThreshold = null;
            }

            // Lists: trim, dedup
            if (c.GeoipBlacklist != null)
                c.GeoipBlacklist = c.GeoipBlacklist
                    .Select(x => x?.Trim())
                    .Where(x => !string.IsNullOrEmpty(x))
                    .Select(x => x!)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();

            if (c.SmtpAllowedSources != null)
                c.SmtpAllowedSources = c.SmtpAllowedSources
                    .Select(x => x?.Trim())
                    .Where(x => !string.IsNullOrEmpty(x))
                    .Select(x => x!)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();

            // Optional global advanced-heuristics switch:
            // if explicitly set to false, default all advanced/strategy rules OFF
            if (c.EnableAdvancedHeuristics == false)
            {
                c.EnableTlsNoSniToIp ??= false;
                c.EnableRareTlsFingerprint ??= false;
                c.EnableTlsCertExpiry ??= false;
                c.EnableSmbToInternet ??= false;
                c.EnableAdminEgress ??= false;
                c.EnableExternalDnsDirect ??= false;
                c.EnableQuicAnomaly ??= false;
                c.EnableAdminLateralSweep ??= false;
                c.EnableDnsTxtSpike ??= false;
                c.EnableSuspiciousUserAgent ??= false;
                c.EnableIcmpOversized ??= false;
                c.EnableDoH ??= false;
                c.EnableRareSshFingerprint ??= false;
                c.EnablePairExfiltration ??= false;
                c.EnableJa4DriftPerSni ??= false;
                c.EnableEncryptedDnsBootstrap ??= false;
                c.EnableAsnNoveltySensitive ??= false;

                c.EnableEncryptedLowAndSlow ??= false;
                c.EnableJa4FanoutSweep ??= false;
                c.EnableUncommonQuicAlpn ??= false;
                c.EnableSniHostMismatch ??= false;
                c.EnableHttpMethodAnomaly ??= false;
                c.EnableSparseHttpPost ??= false;
                c.EnableUnauthorizedVpnEgress ??= false;
                c.EnableHttpBasicAuthToIp ??= false;
                c.EnableAlternateDoHPatterns ??= false;
                c.EnableSuspiciousSniShape ??= false;
            }
        }

        private static void TryWriteTemplate(string path)
        {
            try
            {
                if (File.Exists(path)) return;
                var template = """
                {
                  // Carthago rules template (comments allowed). Remove entries to use code defaults.
                  "enableDns": true,
                  "dnsThreshold": 20,
                  "dnsWindowSeconds": 30,
                  "enableExfiltration": true,
                  "exfilThresholdBytes": 5000000,
                  "exfilWindowSeconds": 60,
                  "enableQuicAnomaly": true,
                  "enableDnsTxtSpike": true,
                  "geoipBlacklist": ["CN","RU","KP","IR"],
                  // Example: "smtpAllowedSources": ["10.0.0.10","10.0.0.11"]
                }
                """;
                File.WriteAllText(path, template);
                Console.WriteLine($"[RuleEngine] Wrote template rules to {path}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RuleEngine] Failed to write rules template: {ex.Message}");
            }
        }
    }
}
