// File: Services/TrafficCaptureService.cs
// SPDX-License-Identifier: MIT

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Carthago.Capture;
using Carthago.Models;
using Carthago.Telemetry; // OtelMetrics.CountRuleHit
using SharpPcap;

namespace Carthago.Services
{
    /// <summary>
    /// Capture + background enrichment (WHOIS/AbuseIPDB) + RuleEngine pipeline.
    /// Supports SharpPcap (default) and ETW capture backends.
    /// UI delivery uses a bounded Channel&lt;T&gt; for predictable latency and no memory bloat.
    /// </summary>
    public sealed class TrafficCaptureService : IDisposable
    {
        // ===== Public events
        public event Action<TrafficRecord>? TrafficRecordReceived;
        public event Action<DetectionEvent>? DetectionEventRaised;
        public event Action<StatsSnapshot>? StatsUpdated;

        // ===== Capture device or source
        private ILiveDevice? _device;
        private ICaptureSource? _captureSource;

        // Service lifetime CTS (UI loop, maintenance, etc.)
        private readonly CancellationTokenSource _serviceCts = new();

        // Per-run CTS (captures and enrich tasks related to a running session)
        private CancellationTokenSource? _runCts;

        // ===== L7 parser
        private readonly PacketHandler _packetHandler = new();

        // ===== UI channel/batching
        private const int UI_DRAIN_MAX_PER_TICK = 100;
        private const int UI_CHANNEL_CAPACITY = 5000;

        private readonly Channel<TrafficRecord> _uiChannel =
            Channel.CreateBounded<TrafficRecord>(new BoundedChannelOptions(UI_CHANNEL_CAPACITY)
            {
                FullMode = BoundedChannelFullMode.Wait, // bounded memory, predictable latency
                SingleReader = true,
                SingleWriter = false
            });

        private readonly DispatcherTimer _uiDrainTimer;
        private Task? _uiReaderTask;

        // ===== Maintenance (cache prune + stats publish)
        private readonly TimeSpan _maintenanceInterval = TimeSpan.FromMinutes(2);
        private Timer? _maintenanceTimer;

        // ===== Stats
        private long _packetsCaptured;
        private long _packetsParsedOk;
        private long _packetsParseErrors;
        private long _packetsDroppedByQueue;
        private long _ruleEventsRaised;
        private long _whoisEnriched;
        private long _reputationEnriched;

        // ===== Filters / UI
        private string? _currentFilter;
        private readonly Dispatcher _dispatcher;
        private readonly BlacklistService? _blacklistService;

        // ===== WHOIS + Reputation
        private const int WHOIS_CONCURRENCY = 4;
        private const int REPUTATION_CONCURRENCY = 4;
        private readonly SemaphoreSlim _whoisLimiter = new(WHOIS_CONCURRENCY, WHOIS_CONCURRENCY);
        private readonly SemaphoreSlim _reputationLimiter = new(REPUTATION_CONCURRENCY, REPUTATION_CONCURRENCY);

        // In-memory caches with TTL + inflight coalescing
        private readonly ConcurrentDictionary<string, CacheEntry<WhoisInfo>> _whoisCache = new(StringComparer.Ordinal);
        private readonly ConcurrentDictionary<string, CacheEntry<ReputationInfo>> _reputationCache = new(StringComparer.Ordinal);
        private readonly ConcurrentDictionary<string, Lazy<Task<WhoisInfo?>>> _whoisInflight = new(StringComparer.Ordinal);
        private readonly ConcurrentDictionary<string, Lazy<Task<ReputationInfo?>>> _reputationInflight = new(StringComparer.Ordinal);

        // TTLs
        private static readonly TimeSpan WhoisTtl = TimeSpan.FromDays(7);
        private static readonly TimeSpan ReputationTtl = TimeSpan.FromHours(12);

        // AbuseIPDB client
        private AbuseIpdbClient? _abuseClient;
        private readonly object _abuseClientLock = new();
        private string? _abuseKeyMutable;

        public string? AbuseIpDbApiKey
        {
            get => _abuseKeyMutable ?? Environment.GetEnvironmentVariable("ABUSEIPDB_API_KEY");
            set
            {
                _abuseKeyMutable = value;
                lock (_abuseClientLock)
                {
                    _abuseClient?.Dispose();
                    _abuseClient = null;
                }
            }
        }

        // ----- Constructors -----
        public TrafficCaptureService()
        {
            _dispatcher = Application.Current?.Dispatcher ?? Dispatcher.CurrentDispatcher;

            _uiDrainTimer = new DispatcherTimer(DispatcherPriority.Background, _dispatcher)
            {
                Interval = TimeSpan.FromMilliseconds(75)
            };
            _uiDrainTimer.Tick += UiDrainTimer_Tick;
            _uiDrainTimer.Start();

            _uiReaderTask = Task.Run(UiChannelReaderLoop, _serviceCts.Token);

            _maintenanceTimer = new Timer(_ => SafeMaintenanceTick(), null,
                _maintenanceInterval, _maintenanceInterval);
        }

        public TrafficCaptureService(BlacklistService blacklistService, Dispatcher dispatcher)
        {
            _blacklistService = blacklistService;
            _dispatcher = dispatcher ?? (Application.Current?.Dispatcher ?? Dispatcher.CurrentDispatcher);

            _uiDrainTimer = new DispatcherTimer(DispatcherPriority.Background, _dispatcher)
            {
                Interval = TimeSpan.FromMilliseconds(75)
            };
            _uiDrainTimer.Tick += UiDrainTimer_Tick;
            _uiDrainTimer.Start();

            _uiReaderTask = Task.Run(UiChannelReaderLoop, _serviceCts.Token);

            _maintenanceTimer = new Timer(_ => SafeMaintenanceTick(), null,
                _maintenanceInterval, _maintenanceInterval);
        }

        public void Dispose()
        {
            try { _uiDrainTimer.Stop(); } catch { }
            try { _maintenanceTimer?.Dispose(); } catch { }

            // Stop current run (if any) but keep service resources orderly
            try
            {
                _runCts?.Cancel();
                _runCts?.Dispose();
                _runCts = null;
            }
            catch { }

            try
            {
                if (_device is not null)
                {
                    _device.OnPacketArrival -= OnPacketArrival;
                    try { _device.StopCapture(); } catch { }
                    try { _device.Close(); } catch { }
                }
            }
            catch { }

            try { _captureSource?.StopAsync(); } catch { }
            try { _captureSource?.Dispose(); } catch { }

            lock (_abuseClientLock) { try { _abuseClient?.Dispose(); } catch { } }

            _whoisLimiter.Dispose();
            _reputationLimiter.Dispose();

            // Now end service lifetime (UI reader will exit)
            try { _serviceCts.Cancel(); } catch { }
            try { _serviceCts.Dispose(); } catch { }
        }

        // ---- capture start/stop ---------------------------------------

        /// <summary>Populates ComboBox with both SharpPcap and ETW choices.</summary>
        public void LoadDevices(ComboBox deviceCombo, Button startButton)
        {
            if (deviceCombo == null || startButton == null) return;

            var devices = new List<(string Label, object Dev)>();
            try
            {
                var pcapDevices = CaptureDeviceList.Instance;
                foreach (var d in pcapDevices)
                {
                    string label = $"Npcap: {d.Description} ({d.Name})";
                    devices.Add((label, d));
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to enumerate Npcap devices: {ex.Message}");
            }

            // Always add ETW option
            devices.Add(("ETW Kernel Capture (no Npcap required)", "ETW"));

            _dispatcher.Invoke(() =>
            {
                deviceCombo.Items.Clear();
                foreach (var it in devices)
                    deviceCombo.Items.Add(new ComboBoxItem { Content = it.Label, Tag = it.Dev });

                if (deviceCombo.Items.Count > 0) deviceCombo.SelectedIndex = 0;
                startButton.IsEnabled = deviceCombo.Items.Count > 0;
            });
        }

        public void StartCapture(ComboBox deviceCombo, Button startButton, Button stopButton)
        {
            if (deviceCombo?.SelectedItem is not ComboBoxItem cbi)
            {
                MessageBox.Show("Select a capture source first.", "Capture",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            // Clean any previous run
            try
            {
                _runCts?.Cancel();
                _runCts?.Dispose();
            }
            catch { }
            _runCts = new CancellationTokenSource();
            var runToken = _runCts.Token;

            try
            {
                // Close any old device
                if (_device is not null)
                {
                    _device.OnPacketArrival -= OnPacketArrival;
                    try { _device.StopCapture(); } catch { }
                    try { _device.Close(); } catch { }
                    _device = null;
                }
                _captureSource?.StopAsync();
                _captureSource?.Dispose();
                _captureSource = null;

                if (cbi.Tag is string s && s.Equals("ETW", StringComparison.OrdinalIgnoreCase))
                {
                    _captureSource = new EtwCapture(_uiChannel);
                    _ = _captureSource.StartAsync(); // internal tokening in ICaptureSource
                }
                else if (cbi.Tag is ILiveDevice dev)
                {
                    StartPcapCapture(dev, _currentFilter);
                }
                else
                {
                    MessageBox.Show("Invalid capture selection.", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                _dispatcher.Invoke(() =>
                {
                    startButton.IsEnabled = false;
                    stopButton.IsEnabled = true;
                    deviceCombo.IsEnabled = false;
                });
            }
            catch (Exception ex)
            {
                try
                {
                    MessageBox.Show($"Failed to start capture: {ex.Message}", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
                catch { }
                try { _runCts?.Cancel(); } catch { }
            }
        }

        public void StopCapture(Button startButton, Button stopButton, ComboBox deviceCombo)
        {
            try
            {
                _runCts?.Cancel();

                if (_device is not null)
                {
                    _device.OnPacketArrival -= OnPacketArrival;
                    try { _device.StopCapture(); } catch { }
                    try { _device.Close(); } catch { }
                }

                _captureSource?.StopAsync();

                _dispatcher.Invoke(() =>
                {
                    startButton.IsEnabled = true;
                    stopButton.IsEnabled = false;
                    deviceCombo.IsEnabled = true;
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to stop capture: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                try { _runCts?.Dispose(); } catch { }
                _runCts = null;
            }
        }

        private void StartPcapCapture(ILiveDevice device, string? captureFilter = null)
        {
            _device = device ?? throw new ArgumentNullException(nameof(device));

            try
            {
                _device.OnPacketArrival += OnPacketArrival;
                _device.Open();

                if (!string.IsNullOrWhiteSpace(captureFilter))
                {
                    try { _device.Filter = captureFilter; }
                    catch (Exception ex) { Console.Error.WriteLine($"Failed to set capture filter '{captureFilter}': {ex.Message}"); }
                }

                _device.StartCapture();
            }
            catch
            {
                // detach if partially wired
                try { _device.OnPacketArrival -= OnPacketArrival; } catch { }
                throw;
            }
        }

        // ---- Packet arrival for SharpPcap ------------------------------
        private void OnPacketArrival(object sender, PacketCapture e)
        {
            Interlocked.Increment(ref _packetsCaptured);
            try
            {
                var rec = _packetHandler.ParsePacket(e);
                if (rec is null) return;

                Interlocked.Increment(ref _packetsParsedOk);

                // Run-bound CT: if capture stopped, enrichment cancels quickly
                var ct = _runCts?.Token ?? _serviceCts.Token;
                _ = EnrichAsync(rec, ct);

                if (!_uiChannel.Writer.TryWrite(rec))
                {
                    Interlocked.Increment(ref _packetsDroppedByQueue);
                    RuleEngine.ReportCaptureDrops(1);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"OnPacketArrival error: {ex.Message}");
                Interlocked.Increment(ref _packetsParseErrors);
            }
        }

        // ---- UI drain --------------------------------------------------
        private async Task UiChannelReaderLoop()
        {
            var reader = _uiChannel.Reader;
            try
            {
                while (await reader.WaitToReadAsync(_serviceCts.Token).ConfigureAwait(false))
                {
                    var batch = new List<TrafficRecord>(UI_DRAIN_MAX_PER_TICK);
                    while (batch.Count < UI_DRAIN_MAX_PER_TICK && reader.TryRead(out var rec))
                        batch.Add(rec);

                    if (batch.Count > 0)
                    {
                        await _dispatcher.InvokeAsync(() =>
                        {
                            foreach (var r in batch)
                            {
                                try { TrafficRecordReceived?.Invoke(r); }
                                catch { /* never throw to UI loop */ }
                            }
                        }, DispatcherPriority.Background);
                    }
                }
            }
            catch (OperationCanceledException) { /* service shutting down */ }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"UiChannelReaderLoop error: {ex.Message}");
            }
        }

        private void UiDrainTimer_Tick(object? sender, EventArgs e)
        {
            // Intentional no-op; UI reader loop performs the dispatch.
        }

        // ---- enrichment + rules ---------------------------------------
        private async Task EnrichAsync(TrafficRecord rec, CancellationToken ct)
        {
            try
            {
                var prefs = PreferencesService.Current;
                bool enableWhois = prefs.EnableWhois;
                bool enableReputation = prefs.EnableReputation;

                // Skip enrichment when both sides are private/special (saves budget)
                var whoisTarget = GetWhoisTarget(rec);
                if (whoisTarget is not null && IsEnrichablePublicIp(whoisTarget))
                {
                    if (enableWhois)
                    {
                        var w = await EnrichWithWhoisAsync(whoisTarget, ct).ConfigureAwait(false);
                        if (w is not null)
                        {
                            rec.WhoisASN = w.Asn ?? rec.WhoisASN;
                            rec.WhoisOrganization = w.Org ?? rec.WhoisOrganization;
                            rec.WhoisCountry = w.CountryCode ?? rec.WhoisCountry;
                            rec.WhoisRegistrar = w.Registrar ?? rec.WhoisRegistrar;
                            rec.WhoisAbuseContact = w.Abuse ?? rec.WhoisAbuseContact;
                            Interlocked.Increment(ref _whoisEnriched);
                        }
                    }

                    if (enableReputation)
                    {
                        var rep = await EnrichWithReputationAsync(whoisTarget, ct).ConfigureAwait(false);
                        if (rep is not null)
                        {
                            rec.ReputationScore = rep.AbuseConfidenceScore;
                            rec.ReputationReports = rep.TotalReports;
                            if (DateTimeOffset.TryParse(rep.LastReportedAt, out var dto))
                                rec.ReputationLastSeen = dto.UtcDateTime;
                            rec.ReputationIsMalicious = IsMalicious(rec.ReputationScore);
                            Interlocked.Increment(ref _reputationEnriched);
                        }
                    }
                }

                var detections = RuleEngine.Evaluate(rec, PreferencesService.Sensitivity);
                if (detections is { Count: > 0 })
                {
                    Interlocked.Add(ref _ruleEventsRaised, detections.Count);
                    foreach (var evt in detections)
                    {
                        if (evt is null) continue; // static analyzer happiness
                        try { OtelMetrics.CountRuleHit(evt.GetType().Name); } catch { /* optional metric */ }
                        RaiseDetection(evt);
                    }
                }
            }
            catch (OperationCanceledException) { /* expected on stop */ }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"EnrichAsync error: {ex.Message}");
            }
        }

        public async Task ManualReputationLookup(TrafficRecord rec)
        {
            if (rec is null) return;
            var ip = GetWhoisTarget(rec) ?? rec.Source ?? rec.Destination;
            if (string.IsNullOrWhiteSpace(ip) || !IsEnrichablePublicIp(ip)) return;

            var ct = _runCts?.Token ?? _serviceCts.Token;

            var rep = await EnrichWithReputationAsync(ip, ct).ConfigureAwait(false);
            if (rep is null) return;

            rec.ReputationScore = rep.AbuseConfidenceScore;
            rec.ReputationReports = rep.TotalReports;
            if (DateTimeOffset.TryParse(rep.LastReportedAt, out var dto))
                rec.ReputationLastSeen = dto.UtcDateTime;
            rec.ReputationIsMalicious = IsMalicious(rec.ReputationScore);

            var detections = RuleEngine.Evaluate(rec, PreferencesService.Sensitivity);
            if (detections is { Count: > 0 })
            {
                Interlocked.Add(ref _ruleEventsRaised, detections.Count);
                foreach (var evt in detections)
                {
                    if (evt is null) continue;
                    try { OtelMetrics.CountRuleHit(evt.GetType().Name); } catch { }
                    RaiseDetection(evt);
                }
            }
        }

        private void RaiseDetection(DetectionEvent evt)
        {
            if (evt is null) return;
            try
            {
                if (_dispatcher.CheckAccess())
                    DetectionEventRaised?.Invoke(evt);
                else
                    _dispatcher.BeginInvoke(() => DetectionEventRaised?.Invoke(evt));
            }
            catch { /* never let UI explode */ }
        }

        private static bool IsMalicious(int? score)
        {
            if (!score.HasValue) return false;
            var threshold = PreferencesService.Sensitivity switch
            {
                Sensitivity.Relaxed => 90,
                Sensitivity.Aggressive => 50,
                _ => 75
            };
            return score.Value >= threshold;
        }

        // ---- WHOIS and Reputation enrichment helpers ------------------
        private async Task<WhoisInfo?> EnrichWithWhoisAsync(string ip, CancellationToken ct)
        {
            if (_whoisCache.TryGetValue(ip, out var cached) && !cached.IsExpired)
                return cached.Value;

            var lazy = _whoisInflight.GetOrAdd(ip, _ =>
                new Lazy<Task<WhoisInfo?>>(async () =>
                {
                    await _whoisLimiter.WaitAsync(ct).ConfigureAwait(false);
                    try
                    {
                        var raw = await WhoisResolver.LookupRawAsync(ip, ct).ConfigureAwait(false);
                        if (string.IsNullOrWhiteSpace(raw)) return null;

                        var info = new WhoisInfo
                        {
                            Asn = WhoisResolver.GetASN(raw),
                            Org = WhoisResolver.GetOrganization(raw) ?? WhoisResolver.GetRegistrar(raw),
                            CountryCode = WhoisResolver.GetCountry(raw),
                            Registrar = WhoisResolver.GetRegistrar(raw),
                            Abuse = WhoisResolver.GetAbuseContact(raw)
                        };
                        _whoisCache[ip] = CacheEntry<WhoisInfo>.From(info, WhoisTtl);
                        return info;
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"WHOIS enrich failed for {ip}: {ex.Message}");
                        return null;
                    }
                    finally
                    {
                        _whoisLimiter.Release();
                    }
                }, LazyThreadSafetyMode.ExecutionAndPublication));

            try { return await lazy.Value.ConfigureAwait(false); }
            finally { _whoisInflight.TryRemove(ip, out _); }
        }

        private async Task<ReputationInfo?> EnrichWithReputationAsync(string ip, CancellationToken ct)
        {
            if (_reputationCache.TryGetValue(ip, out var cached) && !cached.IsExpired)
                return cached.Value;

            var lazy = _reputationInflight.GetOrAdd(ip, _ =>
                new Lazy<Task<ReputationInfo?>>(async () =>
                {
                    await _reputationLimiter.WaitAsync(ct).ConfigureAwait(false);
                    try
                    {
                        var client = GetOrCreateAbuseClient();
                        if (client is null) return null;

                        // Named args to avoid overload ambiguity in some SDKs
                        var resp = await client.CheckAsync(ip: ip, maxAgeInDays: 90, ct: ct).ConfigureAwait(false);
                        if (resp is null) return null;

                        var rep = new ReputationInfo
                        {
                            AbuseConfidenceScore = resp.AbuseConfidenceScore,
                            TotalReports = resp.TotalReports,
                            LastReportedAt = resp.LastReportedAt
                        };
                        _reputationCache[ip] = CacheEntry<ReputationInfo>.From(rep, ReputationTtl);
                        return rep;
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"Reputation enrich failed for {ip}: {ex.Message}");
                        return null;
                    }
                    finally
                    {
                        _reputationLimiter.Release();
                    }
                }, LazyThreadSafetyMode.ExecutionAndPublication));

#pragma warning disable CS8603 // possible null return — caller handles null
            try { return await lazy.Value.ConfigureAwait(false); }
            finally { _reputationInflight.TryRemove(ip, out _); }
#pragma warning restore CS8603
        }

        private AbuseIpdbClient? GetOrCreateAbuseClient()
        {
            var key = AbuseIpDbApiKey;
            if (string.IsNullOrWhiteSpace(key)) return null;
            lock (_abuseClientLock)
            {
                _abuseClient ??= new AbuseIpdbClient(key!);
                return _abuseClient;
            }
        }

        // ---- helpers ---------------------------------------------------
        public void ApplyFilter(string? bpf)
        {
            SetDefaultFilter(bpf);

            // ETW mode? Inform and bail – device-level BPF doesn't exist here.
            if (_captureSource is not null && _device is null)
            {
                try
                {
                    MessageBox.Show(
                        "Filter applies only to Npcap devices. In ETW mode the driver does not support BPF. " +
                        "Select an 'Npcap:' interface to use capture filters.",
                        "Filter not applied (ETW mode)", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch { /* non-UI contexts */ }
                return;
            }

            // No device yet – just store the filter for when capture starts
            if (_device is null)
                return;

            try
            {
                bool wasRunning = _device.Started;

                if (wasRunning)
                {
                    _device.StopCapture();
                    _device.Close();
                }

                _device.Open(); // open fresh handle
                _device.Filter = _currentFilter ?? string.Empty; // set or clear
                if (wasRunning)
                    _device.StartCapture();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"ApplyFilter error: {ex.Message}");
                try
                {
                    MessageBox.Show($"Failed to apply filter:\n{ex.Message}",
                        "Capture filter", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                catch { /* ignore */ }
            }
        }

        public void SetDefaultFilter(string? bpf)
        {
            _currentFilter = string.IsNullOrWhiteSpace(bpf) ? null : bpf.Trim();
        }

        private static bool IsEnrichablePublicIp(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            if (!IPAddress.TryParse(ip, out var addr)) return false;

            // Skip loopback, link-local, private, multicast, etc.
            if (IPAddress.IsLoopback(addr)) return false;

            if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var b = addr.GetAddressBytes();
                // Private
                if (b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168))
                    return false;
                // Link-local 169.254/16 or multicast 224.0.0.0/4
                if (b[0] == 169 && b[1] == 254) return false;
                if (b[0] >= 224 && b[0] <= 239) return false;
            }
            else if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                var s = addr.ToString().ToLowerInvariant();
                if (addr.IsIPv6LinkLocal || addr.IsIPv6SiteLocal || s.StartsWith("fc") || s.StartsWith("fd"))
                    return false; // ULA
                if (s.StartsWith("fe80")) return false; // link-local
                if (s.StartsWith("ff")) return false; // multicast
                if (s == "::1") return false; // loopback
            }

            return true;
        }

        private static string? GetWhoisTarget(TrafficRecord r)
        {
            bool srcPriv = IsPrivateIp(r.Source);
            bool dstPriv = IsPrivateIp(r.Destination);

            if (srcPriv && !dstPriv) return r.Destination;
            if (!srcPriv && dstPriv) return r.Source;
            if (!srcPriv && !dstPriv) return string.IsNullOrWhiteSpace(r.Destination) ? r.Source : r.Destination;
            return null;
        }

        private static bool IsPrivateIp(string? ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            if (!IPAddress.TryParse(ip, out var addr)) return false;

            if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var b = addr.GetAddressBytes();
                return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168);
            }

            if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                var s = addr.ToString().ToLowerInvariant();
                return addr.IsIPv6LinkLocal || addr.IsIPv6SiteLocal || s.StartsWith("fc") || s.StartsWith("fd");
            }
            return false;
        }

        private void SafeMaintenanceTick()
        {
            try
            {
                // prune expired cache entries
                PruneCache(_whoisCache);
                PruneCache(_reputationCache);

                // publish stats snapshot (non-blocking)
                var snap = GetStats();
                try { StatsUpdated?.Invoke(snap); } catch { }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Maintenance tick error: {ex.Message}");
            }
        }

        private static void PruneCache<T>(ConcurrentDictionary<string, CacheEntry<T>> dict)
        {
            foreach (var kvp in dict)
            {
                if (kvp.Value.IsExpired)
                    dict.TryRemove(kvp.Key, out _);
            }
        }

        public StatsSnapshot GetStats() => new()
        {
            PacketsCaptured = Interlocked.Read(ref _packetsCaptured),
            PacketsParsedOk = Interlocked.Read(ref _packetsParsedOk),
            PacketsParseErrors = Interlocked.Read(ref _packetsParseErrors),
            PacketsDroppedByQueue = Interlocked.Read(ref _packetsDroppedByQueue),
            RuleEventsRaised = Interlocked.Read(ref _ruleEventsRaised),
            WhoisEnriched = Interlocked.Read(ref _whoisEnriched),
            ReputationEnriched = Interlocked.Read(ref _reputationEnriched),
            WhoisCacheSize = _whoisCache.Count,
            ReputationCacheSize = _reputationCache.Count
        };

        public void ResetStats()
        {
            Interlocked.Exchange(ref _packetsCaptured, 0);
            Interlocked.Exchange(ref _packetsParsedOk, 0);
            Interlocked.Exchange(ref _packetsParseErrors, 0);
            Interlocked.Exchange(ref _packetsDroppedByQueue, 0);
            Interlocked.Exchange(ref _ruleEventsRaised, 0);
            Interlocked.Exchange(ref _whoisEnriched, 0);
            Interlocked.Exchange(ref _reputationEnriched, 0);
        }

        // ===== simple cache envelope =====
        private sealed record CacheEntry<T>(T Value, DateTimeOffset ExpiresAt)
        {
            public bool IsExpired => DateTimeOffset.UtcNow >= ExpiresAt;
            public static CacheEntry<T> From(T value, TimeSpan ttl) => new(value, DateTimeOffset.UtcNow.Add(ttl));
        }

        private sealed class ReputationInfo
        {
            public int AbuseConfidenceScore { get; set; }
            public int TotalReports { get; set; }
            public string? LastReportedAt { get; set; }
        }

        private sealed class WhoisInfo
        {
            public string? Asn { get; set; }
            public string? Org { get; set; }
            public string? CountryCode { get; set; }
            public string? Registrar { get; set; }
            public string? Abuse { get; set; }
        }

        // ======= Stats DTO =======
        public sealed class StatsSnapshot
        {
            public long PacketsCaptured { get; init; }
            public long PacketsParsedOk { get; init; }
            public long PacketsParseErrors { get; init; }
            public long PacketsDroppedByQueue { get; init; }
            public long RuleEventsRaised { get; init; }
            public long WhoisEnriched { get; init; }
            public long ReputationEnriched { get; init; }
            public int WhoisCacheSize { get; init; }
            public int ReputationCacheSize { get; init; }
        }
    }
}
