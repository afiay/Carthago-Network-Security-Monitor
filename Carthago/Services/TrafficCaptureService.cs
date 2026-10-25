// File: Services/TrafficCaptureService.cs
// SPDX-License-Identifier: MIT

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
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
        public event Action<Exception>? CaptureFailed;

        // ===== Capture device or source
        private readonly object _lifecycleLock = new();
        private ILiveDevice? _device;
        private ICaptureSource? _captureSource;
        private CancellationTokenSource? _runCts;
        private int _disposed;
        private string? _lastCaptureError;

        public string? LastCaptureError => Volatile.Read(ref _lastCaptureError);

        // ETW emits traffic records rather than raw packets. Route those records
        // through the same enrichment/detection path as Npcap packets.
        private Channel<TrafficRecord>? _etwChannel;
        private Task? _etwReaderTask;
        private Task? _etwCaptureTask;

        private readonly CancellationTokenSource _serviceCts = new();
        private readonly PacketHandler _packetHandler = new();

        private const int UiBatchSize = 100;
        private const int UiQueueCapacity = 5000;
        private const int EnrichmentQueueCapacity = 4096;
        private const int EnrichmentWorkerCount = 4;

        private sealed record EnrichmentWork(TrafficRecord Record, CancellationToken RunToken);

        private readonly Channel<TrafficRecord> _uiChannel =
            Channel.CreateBounded<TrafficRecord>(new BoundedChannelOptions(UiQueueCapacity)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
                SingleWriter = false
            });

        private readonly Channel<EnrichmentWork> _enrichmentChannel =
            Channel.CreateBounded<EnrichmentWork>(new BoundedChannelOptions(EnrichmentQueueCapacity)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = false,
                SingleWriter = false
            });

        private readonly Task[] _enrichmentWorkers = new Task[EnrichmentWorkerCount];
        private readonly Task _uiReaderTask;
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
        private long _enrichmentFallbacks;

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
            : this(null, Application.Current?.Dispatcher ?? Dispatcher.CurrentDispatcher)
        {
        }

        public TrafficCaptureService(BlacklistService? blacklistService, Dispatcher dispatcher)
        {
            _blacklistService = blacklistService;
            _dispatcher = dispatcher ?? (Application.Current?.Dispatcher ?? Dispatcher.CurrentDispatcher);

            _uiReaderTask = Task.Run(UiChannelReaderLoop);
            for (int i = 0; i < _enrichmentWorkers.Length; i++)
                _enrichmentWorkers[i] = Task.Run(EnrichmentWorkerLoop);

            _maintenanceTimer = new Timer(_ => SafeMaintenanceTick(), null,
                _maintenanceInterval, _maintenanceInterval);
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

            StopCurrentCapture();
            _maintenanceTimer?.Dispose();
            _maintenanceTimer = null;

            _serviceCts.Cancel();
            _uiChannel.Writer.TryComplete();
            _enrichmentChannel.Writer.TryComplete();

            // Dispose shared resources only after workers have released them.
            // Do not synchronously wait for the UI reader: it may be awaiting
            // Dispatcher.InvokeAsync on the very thread calling Dispose().
            _ = Task.WhenAll(_enrichmentWorkers).ContinueWith(_ =>
            {
                lock (_abuseClientLock)
                {
                    try { _abuseClient?.Dispose(); } catch (Exception ex) { Log(ex); }
                    _abuseClient = null;
                }
                _whoisLimiter.Dispose();
                _reputationLimiter.Dispose();
                _serviceCts.Dispose();
            }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }

        private CancellationToken GetRunToken()
        {
            lock (_lifecycleLock)
                return _runCts?.Token ?? _serviceCts.Token;
        }

        private static void Log(Exception ex)
            => Console.Error.WriteLine($"[TrafficCaptureService] {ex.GetType().Name}: {ex.Message}");

        private void StopCurrentCapture()
        {
            CancellationTokenSource? run;
            ILiveDevice? device;
            ICaptureSource? source;
            Channel<TrafficRecord>? etwChannel;

            lock (_lifecycleLock)
            {
                run = _runCts;
                _runCts = null;
                device = _device;
                _device = null;
                source = _captureSource;
                _captureSource = null;
                etwChannel = _etwChannel;
                _etwChannel = null;
            }

            try { run?.Cancel(); } catch (Exception ex) { Log(ex); }

            if (device != null)
            {
                try { device.OnPacketArrival -= OnPacketArrival; } catch (Exception ex) { Log(ex); }
                try { device.StopCapture(); } catch (Exception ex) { Log(ex); }
                try { device.Close(); } catch (Exception ex) { Log(ex); }
            }

            if (source != null)
            {
                try { source.StopAsync().GetAwaiter().GetResult(); } catch (Exception ex) { Log(ex); }
                try { source.Dispose(); } catch (Exception ex) { Log(ex); }
            }

            etwChannel?.Writer.TryComplete();
            run?.Dispose();
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
            if (Volatile.Read(ref _disposed) != 0)
                throw new ObjectDisposedException(nameof(TrafficCaptureService));

            if (deviceCombo?.SelectedItem is not ComboBoxItem choice)
            {
                MessageBox.Show("Select a capture source first.", "Capture",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            // Capture sources must not overlap: release the previous session first.
            StopCurrentCapture();
            Volatile.Write(ref _lastCaptureError, null);
            var run = CancellationTokenSource.CreateLinkedTokenSource(_serviceCts.Token);
            lock (_lifecycleLock)
                _runCts = run;

            try
            {
                if (choice.Tag is string mode && mode.Equals("ETW", StringComparison.OrdinalIgnoreCase))
                {
                    var etwChannel = Channel.CreateBounded<TrafficRecord>(
                        new BoundedChannelOptions(UiQueueCapacity)
                        {
                            FullMode = BoundedChannelFullMode.Wait,
                            SingleReader = true,
                            SingleWriter = false
                        });
                    var source = new EtwCapture(etwChannel);
                    lock (_lifecycleLock)
                    {
                        _etwChannel = etwChannel;
                        _captureSource = source;
                    }

                    _etwReaderTask = Task.Run(() => EtwReaderLoop(etwChannel.Reader, run.Token));
                    _etwCaptureTask = source.StartAsync();
                    CaptureTaskFailureObserver.Observe(_etwCaptureTask,
                        error => HandleCaptureTaskFailure(run, error, deviceCombo, startButton, stopButton));
                }
                else if (choice.Tag is ILiveDevice device)
                {
                    StartPcapCapture(device, _currentFilter);
                }
                else
                {
                    StopCurrentCapture();
                    MessageBox.Show("Invalid capture selection.", "Capture",
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
                StopCurrentCapture();
                Log(ex);
                Volatile.Write(ref _lastCaptureError, ex.Message);
                CaptureFailed?.Invoke(ex);
                MessageBox.Show($"Failed to start capture: {ex.Message}", "Capture",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public void StopCapture(Button startButton, Button stopButton, ComboBox deviceCombo)
        {
            StopCurrentCapture();
            if (Volatile.Read(ref _disposed) != 0) return;
            Volatile.Write(ref _lastCaptureError, null);

            _dispatcher.Invoke(() =>
            {
                startButton.IsEnabled = true;
                stopButton.IsEnabled = false;
                deviceCombo.IsEnabled = true;
            });
        }

        private void HandleCaptureTaskFailure(
            CancellationTokenSource run, Exception error,
            ComboBox deviceCombo, Button startButton, Button stopButton)
        {
            Log(error);
            if (_dispatcher.HasShutdownStarted || _dispatcher.HasShutdownFinished) return;

            _ = _dispatcher.BeginInvoke(new Action(() =>
            {
                // A stopped or replaced capture must not corrupt the new session's UI.
                lock (_lifecycleLock)
                {
                    if (!ReferenceEquals(_runCts, run) || _disposed != 0)
                        return;
                }

                StopCurrentCapture();
                Volatile.Write(ref _lastCaptureError, error.Message);
                startButton.IsEnabled = true;
                stopButton.IsEnabled = false;
                deviceCombo.IsEnabled = true;
                CaptureFailed?.Invoke(error);
            }), DispatcherPriority.Normal);
        }

        private void StartPcapCapture(ILiveDevice device, string? captureFilter = null)
        {
            if (device == null) throw new ArgumentNullException(nameof(device));
            lock (_lifecycleLock) _device = device;

            try
            {
                device.OnPacketArrival += OnPacketArrival;
                device.Open();

                if (!string.IsNullOrWhiteSpace(captureFilter))
                {
                    try { device.Filter = captureFilter; }
                    catch (Exception ex) { Console.Error.WriteLine($"Failed to set capture filter '{captureFilter}': {ex.Message}"); }
                }

                device.StartCapture();
            }
            catch
            {
                // detach if partially wired
                try { device.OnPacketArrival -= OnPacketArrival; } catch { }
                try { device.Close(); } catch { }
                throw;
            }
        }

        // ---- Capture pipelines ----------------------------------------
        private void OnPacketArrival(object sender, PacketCapture packet)
        {
            CancellationToken token;
            lock (_lifecycleLock)
            {
                if (_runCts is null || _runCts.IsCancellationRequested || _disposed != 0)
                    return;
                if (sender is ILiveDevice senderDevice && !ReferenceEquals(senderDevice, _device))
                    return; // ignore a late callback from a previous capture device
                token = _runCts.Token;
            }

            Interlocked.Increment(ref _packetsCaptured);
            try
            {
                var record = _packetHandler.ParsePacket(packet);
                if (record is null) return;

                Interlocked.Increment(ref _packetsParsedOk);
                PublishRecord(record, token);
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _packetsParseErrors);
                Log(ex);
            }
        }

        private async Task EtwReaderLoop(ChannelReader<TrafficRecord> reader, CancellationToken token)
        {
            try
            {
                await foreach (var record in reader.ReadAllAsync(token).ConfigureAwait(false))
                {
                    Interlocked.Increment(ref _packetsCaptured);
                    Interlocked.Increment(ref _packetsParsedOk);
                    PublishRecord(record, token);
                }
            }
            catch (OperationCanceledException) { /* capture stopped */ }
            catch (Exception ex) { Log(ex); }
        }

        private void PublishRecord(TrafficRecord record, CancellationToken runToken)
        {
            if (runToken.IsCancellationRequested || _serviceCts.IsCancellationRequested)
                return;

            // UI pressure must never suppress rule evaluation.
            if (!_uiChannel.Writer.TryWrite(record))
            {
                Interlocked.Increment(ref _packetsDroppedByQueue);
                RuleEngine.ReportCaptureDrops(1);
            }

            if (!_enrichmentChannel.Writer.TryWrite(new EnrichmentWork(record, runToken)))
            {
                // An overloaded enrichment queue must not silently suppress
                // local detections. Evaluate basic rules without remote lookups.
                Interlocked.Increment(ref _enrichmentFallbacks);
                EvaluateRules(record);
            }
        }

        private async Task EnrichmentWorkerLoop()
        {
            try
            {
                await foreach (var work in _enrichmentChannel.Reader.ReadAllAsync(_serviceCts.Token)
                                   .ConfigureAwait(false))
                {
                    if (!work.RunToken.IsCancellationRequested)
                        await EnrichAsync(work.Record, work.RunToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { /* service disposed */ }
            catch (Exception ex) { Log(ex); }
        }

        // ---- UI drain --------------------------------------------------
        private async Task UiChannelReaderLoop()
        {
            var reader = _uiChannel.Reader;
            try
            {
                while (await reader.WaitToReadAsync(_serviceCts.Token).ConfigureAwait(false))
                {
                    var batch = new List<TrafficRecord>(UiBatchSize);
                    while (batch.Count < UiBatchSize && reader.TryRead(out var rec))
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

                EvaluateRules(rec);
            }
            catch (OperationCanceledException) { /* expected on stop */ }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"EnrichAsync error: {ex.Message}");
            }
        }

        private void EvaluateRules(TrafficRecord rec)
        {
            try
            {
                var detections = RuleEngine.Evaluate(rec, PreferencesService.Sensitivity);
                if (detections is not { Count: > 0 }) return;

                Interlocked.Add(ref _ruleEventsRaised, detections.Count);
                foreach (var evt in detections)
                {
                    if (evt is null) continue;
                    try { OtelMetrics.CountRuleHit(evt.GetType().Name); } catch { /* optional metrics */ }
                    RaiseDetection(evt);
                }
            }
            catch (Exception ex) { Log(ex); }
        }

        public async Task ManualReputationLookup(TrafficRecord rec)
        {
            if (rec is null || Volatile.Read(ref _disposed) != 0) return;
            var ip = GetWhoisTarget(rec) ?? rec.Source ?? rec.Destination;
            if (string.IsNullOrWhiteSpace(ip) || !IsEnrichablePublicIp(ip)) return;

            var ct = GetRunToken();
            var rep = await EnrichWithReputationAsync(ip, ct).ConfigureAwait(false);
            if (rep is null || ct.IsCancellationRequested) return;

            rec.ReputationScore = rep.AbuseConfidenceScore;
            rec.ReputationReports = rep.TotalReports;
            if (DateTimeOffset.TryParse(rep.LastReportedAt, out var dto))
                rec.ReputationLastSeen = dto.UtcDateTime;
            rec.ReputationIsMalicious = IsMalicious(rec.ReputationScore);

            EvaluateRules(rec);
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

            if (_captureSource != null && _device == null)
            {
                MessageBox.Show("BPF capture filters are available only with Npcap, not ETW.",
                    "Capture filter", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var device = _device;
            if (device == null) return;

            try
            {
                bool running = device.Started;
                if (running)
                {
                    device.StopCapture();
                    device.Close();
                    device.Open();
                }
                device.Filter = _currentFilter ?? string.Empty;
                if (running)
                    device.StartCapture();
            }
            catch (Exception ex)
            {
                Log(ex);
                MessageBox.Show($"Failed to apply capture filter: {ex.Message}",
                    "Capture filter", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public void SetDefaultFilter(string? bpf)
        {
            _currentFilter = string.IsNullOrWhiteSpace(bpf) ? null : bpf.Trim();
        }

        private static bool IsEnrichablePublicIp(string ip)
        {
            if (!IPAddress.TryParse(ip, out var address) || IPAddress.IsLoopback(address))
                return false;

            if (address.IsIPv4MappedToIPv6)
                address = address.MapToIPv4();

            var bytes = address.GetAddressBytes();
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                byte a = bytes[0], b = bytes[1], c = bytes[2];
                if (a == 0 || a == 10 || a == 127 || a >= 224) return false;
                if (a == 100 && b >= 64 && b <= 127) return false; // CGNAT
                if (a == 169 && b == 254) return false; // link local
                if (a == 172 && b >= 16 && b <= 31) return false;
                if (a == 192 && b == 168) return false;
                if (a == 192 && b == 0 && c == 0) return false;
                if (a == 192 && b == 0 && c == 2) return false; // TEST-NET-1
                if (a == 198 && (b == 18 || b == 19)) return false; // benchmarking
                if (a == 198 && b == 51 && c == 100) return false; // TEST-NET-2
                if (a == 203 && b == 0 && c == 113) return false; // TEST-NET-3
                return true;
            }

            if (address.AddressFamily != AddressFamily.InterNetworkV6)
                return false;
            if (address.Equals(IPAddress.IPv6None) || address.Equals(IPAddress.IPv6Any))
                return false;
            if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast)
                return false;
            if ((bytes[0] & 0xFE) == 0xFC) return false; // ULA
            if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8)
                return false; // documentation range
            return true;
        }

        private static string? GetWhoisTarget(TrafficRecord record)
        {
            bool srcPublic = IsEnrichablePublicIp(record.Source ?? string.Empty);
            bool dstPublic = IsEnrichablePublicIp(record.Destination ?? string.Empty);
            if (srcPublic && dstPublic) return record.Destination;
            if (srcPublic) return record.Source;
            if (dstPublic) return record.Destination;
            return null;
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
                try
                {
                    if (_dispatcher.CheckAccess()) StatsUpdated?.Invoke(snap);
                    else _dispatcher.BeginInvoke(DispatcherPriority.Background,
                        new Action(() => { if (Volatile.Read(ref _disposed) == 0) StatsUpdated?.Invoke(snap); }));
                }
                catch (Exception ex) { Log(ex); }
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
            EnrichmentFallbacks = Interlocked.Read(ref _enrichmentFallbacks),
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
            Interlocked.Exchange(ref _enrichmentFallbacks, 0);
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
            public long EnrichmentFallbacks { get; init; }
            public int WhoisCacheSize { get; init; }
            public int ReputationCacheSize { get; init; }
        }
    }
}
