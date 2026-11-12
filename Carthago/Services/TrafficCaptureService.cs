// File: Services/TrafficCaptureService.cs
// SPDX-License-Identifier: MIT

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Globalization;
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
using Carthago.Services.Benchmarking;
using Carthago.Services.Geo;
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
        /// <summary>UI-only coalescing hook; independent of detection and record delivery.</summary>
        public event Action<IReadOnlyList<TrafficRecord>>? TrafficBatchReceived;
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

        private readonly Channel<CaptureSessionRecord<TrafficRecord>> _uiChannel =
            Channel.CreateBounded<CaptureSessionRecord<TrafficRecord>>(new BoundedChannelOptions(UiQueueCapacity)
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
        private readonly EnrichmentProviderHealth _providerHealth = new();
        private readonly SemaphoreSlim _vpnLimiter = new(4, 4);
        private static readonly TimeSpan RemoteLookupBudget = TimeSpan.FromSeconds(3);
        private long _uiRecordsDelivered;
        private long _uiBatchesDelivered;
        private long _uiBatchMaxDurationMs;
        private long _uiBatchLastDurationMs;
        private long _uiOldestBatchWaitMs;
        private long _uiDispatcherWaitMs;
        private long _uiMaxDispatcherWaitMs;
        private long _uiSubscriberBatchMs;
        private long _uiSkippedCanceled;
        private readonly Timer? _uiDiagnosticsTimer;
        private readonly string? _uiDiagnosticsPath;
        private int _uiDiagnosticsWriting;
        private long _captureStartedTicks;
        private long _lastCapturedTicks;
        private long _lastUiDeliveredTicks;
        private long _capturedAtStart;
        private long _deliveredAtStart;
        private long _droppedAtStart;
        private long _parsedAtStart;
        private long _parseErrorsAtStart;

        // ===== Filters / UI
        private string? _currentFilter;
        private IPAddress? _activeLanHost;
        private readonly Dispatcher _dispatcher;
        private readonly BlacklistService? _blacklistService;
        private readonly GeoIpService _geoIpService = new();
        private readonly object _geoIpLock = new();

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

            // Explicit opt-in; no filesystem writes in normal monitoring sessions.
            _uiDiagnosticsPath = Environment.GetEnvironmentVariable("CARTHAGO_UI_DIAG_PATH");
            if (!string.IsNullOrWhiteSpace(_uiDiagnosticsPath))
                _uiDiagnosticsTimer = new Timer(_ => WriteUiDiagnostics(), null,
                    TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));

            _uiReaderTask = Task.Run(UiChannelReaderLoop);
            CaptureTaskFailureObserver.Observe(_uiReaderTask, HandleUiDrainFailure);
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
            _uiDiagnosticsTimer?.Dispose();

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
                try { _geoIpService.Dispose(); } catch (Exception ex) { Log(ex); }
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
                _activeLanHost = null;
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

            var devices = new List<(string Label, object Dev, string Tooltip)>();

            // Npcap normally supplies a vendor description and an internal NPF GUID.
            // Match the GUID against Windows network interface IDs for the familiar
            // "Wi-Fi", "Ethernet", or user-renamed adapter alias.
            var windowsAdapters = new List<CaptureAdapterIdentity>();
            try
            {
                foreach (var adapter in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                    windowsAdapters.Add(new CaptureAdapterIdentity(adapter.Id, adapter.Name, adapter.Description));
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Windows adapter names unavailable; using Npcap descriptions: {ex.Message}");
            }

            try
            {
                var pcapDevices = CaptureDeviceList.Instance;
                foreach (var d in pcapDevices)
                {
                    string label = CaptureDeviceLabelFormatter.FormatNpcapLabel(d.Name, d.Description, windowsAdapters);
                    string tooltip = $"{label}\nNpcap description: {d.Description}\nCapture device ID: {d.Name}";
                    devices.Add((label, d, tooltip));
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to enumerate Npcap devices: {ex.Message}");
            }

            // Always add ETW option
            devices.Add(("ETW Kernel Capture (no Npcap required)", "ETW",
                "Windows Event Tracing capture; does not use an Npcap adapter."));

            _dispatcher.Invoke(() =>
            {
                deviceCombo.Items.Clear();
                foreach (var it in devices)
                    deviceCombo.Items.Add(new ComboBoxItem
                    {
                        Content = it.Label,
                        Tag = it.Dev,
                        ToolTip = it.Tooltip
                    });

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

            if (choice.Tag is LanCaptureSelection selectedHost)
            {
                var proceed = MessageBox.Show(
                    LanCaptureDiscovery.FormatVisibilityNotice(selectedHost.Address) +
                    "\n\nCarthago will send one ARP presence check when capture starts so a responding " +
                    "neighbor can appear as link-layer evidence.\n\nStart this local-visibility host filter?",
                    "LAN host filter — local visibility only",
                    MessageBoxButton.OKCancel, MessageBoxImage.Information);
                if (proceed != MessageBoxResult.OK)
                    return;
            }

            // Capture sources must not overlap: release the previous session first.
            StopCurrentCapture();
            Volatile.Write(ref _lastCaptureError, null);
            Interlocked.Exchange(ref _capturedAtStart, Interlocked.Read(ref _packetsCaptured));
            Interlocked.Exchange(ref _deliveredAtStart, Interlocked.Read(ref _uiRecordsDelivered));
            Interlocked.Exchange(ref _droppedAtStart, Interlocked.Read(ref _packetsDroppedByQueue));
            Interlocked.Exchange(ref _parsedAtStart, Interlocked.Read(ref _packetsParsedOk));
            Interlocked.Exchange(ref _parseErrorsAtStart, Interlocked.Read(ref _packetsParseErrors));
            Interlocked.Exchange(ref _lastCapturedTicks, 0);
            Interlocked.Exchange(ref _lastUiDeliveredTicks, 0);
            Interlocked.Exchange(ref _captureStartedTicks, DateTime.UtcNow.Ticks);
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
                    CapturePipelineFailureObserver.Observe(_etwCaptureTask, _etwReaderTask,
                        (stage, error) =>
                        {
                            Log(new InvalidOperationException($"ETW {stage} failed", error));
                            HandleCaptureTaskFailure(run, error, deviceCombo, startButton, stopButton);
                        });
                }
                else if (choice.Tag is LanCaptureSelection host)
                {
                    // Explicit device selection narrows this capture only.
                    // Fail closed if the host filter cannot be installed.
                    lock (_lifecycleLock) _activeLanHost = host.Address;
                    StartPcapCapture(host.Device,
                        LanCaptureDiscovery.ComposeFilter(_currentFilter, host.Address), requireFilter: true);
                    TrySendLanPresenceProbe(host);
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

        private void StartPcapCapture(ILiveDevice device, string? captureFilter = null, bool requireFilter = false)
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
                    catch (Exception ex) when (!requireFilter)
                    { Console.Error.WriteLine($"Failed to set capture filter '{captureFilter}': {ex.Message}"); }
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

        private static void TrySendLanPresenceProbe(LanCaptureSelection host)
        {
            if (host.LocalInterface is null || host.Device.MacAddress is null)
                return;

            try
            {
                host.Device.SendPacket(NpcapArpDiscovery.BuildRequest(
                    host.Device.MacAddress,
                    host.LocalInterface.Address,
                    host.Address));
            }
            catch (Exception ex)
            {
                // The capture is still useful for naturally occurring local
                // traffic even if this optional one-shot presence check fails.
                Console.Error.WriteLine($"LAN presence check failed for {host.Address}: {ex.Message}");
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
            Interlocked.Exchange(ref _lastCapturedTicks, DateTime.UtcNow.Ticks);
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
                    Interlocked.Exchange(ref _lastCapturedTicks, DateTime.UtcNow.Ticks);
                    Interlocked.Increment(ref _packetsParsedOk);
                    PublishRecord(record, token);
                }
            }
            catch (OperationCanceledException) { /* capture stopped */ }
            catch (Exception ex)
            {
                Log(ex);
                throw; // A dead record reader must be surfaced as capture failure.
            }
        }

        private void PublishRecord(TrafficRecord record, CancellationToken runToken)
        {
            if (runToken.IsCancellationRequested || _serviceCts.IsCancellationRequested)
                return;

            EndpointIpEnrichment.Apply(record);

            // UI pressure must never suppress rule evaluation.
            if (!_uiChannel.Writer.TryWrite(new CaptureSessionRecord<TrafficRecord>(record, runToken)))
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
            try
            {
                await CaptureUiDrain.RunAsync(_uiChannel.Reader, UiBatchSize, async batch =>
                {
                    if (batch.Count > 0)
                    {
                        var ageMs = Math.Max(0, (DateTime.UtcNow.Ticks - batch[0].EnqueuedUtcTicks) / TimeSpan.TicksPerMillisecond);
                        Interlocked.Exchange(ref _uiOldestBatchWaitMs, ageMs);
                    }
                    var queuedAt = Stopwatch.GetTimestamp();
                    await _dispatcher.InvokeAsync(() =>
                    {
                        var dispatcherWaitMs = (long)(1000.0 * (Stopwatch.GetTimestamp() - queuedAt) / Stopwatch.Frequency);
                        Interlocked.Exchange(ref _uiDispatcherWaitMs, dispatcherWaitMs);
                        long maxWait;
                        do
                        {
                            maxWait = Interlocked.Read(ref _uiMaxDispatcherWaitMs);
                            if (dispatcherWaitMs <= maxWait) break;
                        } while (Interlocked.CompareExchange(ref _uiMaxDispatcherWaitMs, dispatcherWaitMs, maxWait) != maxWait);
                        var stopwatch = Stopwatch.StartNew();
                        var subscriberMs = 0L;
                        var delivered = new List<TrafficRecord>(batch.Count);
                        foreach (var pending in batch)
                        {
                            try
                            {
                                var didDeliver = pending.TryDeliver(r =>
                                {
                                    var subscriberClock = Stopwatch.StartNew();
                                    TrafficRecordReceived?.Invoke(r);
                                    subscriberClock.Stop();
                                    subscriberMs += subscriberClock.ElapsedMilliseconds;
                                    delivered.Add(r);
                                    Interlocked.Increment(ref _uiRecordsDelivered);
                                    Interlocked.Exchange(ref _lastUiDeliveredTicks, DateTime.UtcNow.Ticks);
                                });
                                if (!didDeliver) Interlocked.Increment(ref _uiSkippedCanceled);
                            }
                            catch (Exception ex) { Log(ex); /* keep other records flowing */ }
                        }
                        // A single bounded collection notification per successful batch.
                        // Exceptions here must never stop the capture or rule pipeline.
                        try { if (delivered.Count != 0) TrafficBatchReceived?.Invoke(delivered); }
                        catch (Exception ex) { Log(ex); }
                        Interlocked.Exchange(ref _uiSubscriberBatchMs, subscriberMs);
                        stopwatch.Stop();
                        var ms = stopwatch.ElapsedMilliseconds;
                        Interlocked.Increment(ref _uiBatchesDelivered);
                        Interlocked.Exchange(ref _uiBatchLastDurationMs, ms);
                        long previous;
                        do
                        {
                            previous = Interlocked.Read(ref _uiBatchMaxDurationMs);
                            if (ms <= previous) break;
                        } while (Interlocked.CompareExchange(ref _uiBatchMaxDurationMs, ms, previous) != previous);
                    }, DispatcherPriority.Background);
                }, _serviceCts.Token).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log(ex);
                throw; // Observer reports the terminal UI-drain failure.
            }
        }

        private void HandleUiDrainFailure(Exception error)
        {
            Log(error);
            if (Volatile.Read(ref _disposed) != 0 || _dispatcher.HasShutdownStarted || _dispatcher.HasShutdownFinished)
                return;

            _ = _dispatcher.BeginInvoke(new Action(() =>
            {
                if (Volatile.Read(ref _disposed) != 0) return;
                StopCurrentCapture();
                Volatile.Write(ref _lastCaptureError, $"UI record delivery stopped: {error.Message}");
                CaptureFailed?.Invoke(error);
            }), DispatcherPriority.Normal);
        }

        private void WriteUiDiagnostics()
        {
            if (string.IsNullOrWhiteSpace(_uiDiagnosticsPath) ||
                Interlocked.Exchange(ref _uiDiagnosticsWriting, 1) != 0) return;
            try
            {
                var path = _uiDiagnosticsPath;
                var folder = Path.GetDirectoryName(path);
                if (!string.IsNullOrWhiteSpace(folder)) Directory.CreateDirectory(folder);
                var header = "timestampUtc,queueDepth,captured,uiDelivered,queueDrops,batches,oldestBatchWaitMs,dispatcherWaitMs,maxDispatcherWaitMs,subscriberBatchMs,skippedCanceled" + Environment.NewLine;
                var row = string.Join(",", new[]
                {
                    DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                    _uiChannel.Reader.Count.ToString(CultureInfo.InvariantCulture),
                    Interlocked.Read(ref _packetsCaptured).ToString(CultureInfo.InvariantCulture),
                    Interlocked.Read(ref _uiRecordsDelivered).ToString(CultureInfo.InvariantCulture),
                    Interlocked.Read(ref _packetsDroppedByQueue).ToString(CultureInfo.InvariantCulture),
                    Interlocked.Read(ref _uiBatchesDelivered).ToString(CultureInfo.InvariantCulture),
                    Interlocked.Read(ref _uiOldestBatchWaitMs).ToString(CultureInfo.InvariantCulture),
                    Interlocked.Read(ref _uiDispatcherWaitMs).ToString(CultureInfo.InvariantCulture),
                    Interlocked.Read(ref _uiMaxDispatcherWaitMs).ToString(CultureInfo.InvariantCulture),
                    Interlocked.Read(ref _uiSubscriberBatchMs).ToString(CultureInfo.InvariantCulture),
                    Interlocked.Read(ref _uiSkippedCanceled).ToString(CultureInfo.InvariantCulture)
                }) + Environment.NewLine;
                if (!File.Exists(path)) File.AppendAllText(path, header);
                File.AppendAllText(path, row);
            }
            catch (Exception ex) { Log(ex); }
            finally { Interlocked.Exchange(ref _uiDiagnosticsWriting, 0); }
        }

        // ---- enrichment + rules ---------------------------------------
        private Task EnrichAsync(TrafficRecord rec, CancellationToken ct)
        {
            void Report(string stage, Exception ex)
                => Console.Error.WriteLine($"Enrichment {stage} error: {ex.Message}");

            Task Stage(string name, Func<Task> action)
                => EnrichmentEvaluationGuard.RunStageAsync(action, ex => Report(name, ex), ct);

            return EnrichmentEvaluationGuard.RunAsync(async () =>
            {
                await Stage("geo", () =>
                {
                    EnrichGeo(rec);
                    return Task.CompletedTask;
                }).ConfigureAwait(false);

                await Stage("process", async () =>
                {
                    if (rec.ProcessId > 0)
                    {
                        rec.ProcessAttribution ??= "CaptureProvided";
                        return; // Do not replace capture-provided process identity.
                    }
                    if ((!rec.IsTcp && !rec.IsUdp)
                        || (rec.SourcePort is not > 0 && rec.DestinationPort is not > 0))
                    {
                        rec.ProcessAttribution = "NotApplicable";
                        return;
                    }
                    if (rec.SrcIsLocalHost != true && rec.DstIsLocalHost != true)
                    {
                        rec.ProcessAttribution = rec.SrcIsLocalHost == false && rec.DstIsLocalHost == false
                            ? "NotLocal" : "LocalHostUnknown";
                        return;
                    }

                    var process = await Task.Run(() => WindowsProcessResolver.ResolveProcess(
                        rec.Source ?? string.Empty, rec.SourcePort,
                        rec.Destination ?? string.Empty, rec.DestinationPort,
                        rec.Protocol ?? string.Empty,
                        rec.SrcIsLocalHost == true, rec.DstIsLocalHost == true), ct).ConfigureAwait(false);

                    if (process is { ProcessId: > 0 })
                    {
                        rec.ProcessId = process.ProcessId;
                        rec.ProcessName = process.ProcessName;
                        rec.ProcessAttribution = rec.IsTcp ? "TcpSocketTable" : "UdpLocalBinding";
                    }
                    else
                    {
                        rec.ProcessAttribution = "Unresolved";
                        rec.ProcessName ??= "Unknown";
                    }
                }).ConfigureAwait(false);

                // Local process hints remain available even if remote classification times out.
                rec.LocalVpnProcessHint = rec.ProcessId > 0 && ProcessNameSignal.IsVpnProcess(rec.ProcessName);
                var prefs = PreferencesService.Current;
                var target = GetWhoisTarget(rec);
                if (target is null)
                {
                    rec.WhoisEnrichmentStatus = "NotApplicable";
                    rec.ReputationEnrichmentStatus = "NotApplicable";
                    rec.VpnEnrichmentStatus = "NotApplicable";
                    return;
                }

                rec.WhoisEnrichmentStatus = prefs.EnableWhois ? "Pending" : "Disabled";
                rec.ReputationEnrichmentStatus = prefs.EnableReputation ? "Pending" : "Disabled";

                if (prefs.EnableWhois)
                {
                    await Stage("whois", async () =>
                    {
                        var lookup = await _providerHealth.LookupAsync("whois",
                            token => EnrichWithWhoisAsync(target, token), RemoteLookupBudget, ct).ConfigureAwait(false);
                        rec.WhoisEnrichmentStatus = lookup.Status.ToString();
                        var w = lookup.Value;
                        if (w is null) return;
                        rec.WhoisLookupIp = target;
                        rec.WhoisASN = w.Asn ?? rec.WhoisASN;
                        rec.WhoisOrganization = w.Org ?? rec.WhoisOrganization;
                        rec.WhoisCountry = w.CountryCode ?? rec.WhoisCountry;
                        rec.WhoisRegistrar = w.Registrar ?? rec.WhoisRegistrar;
                        rec.WhoisAbuseContact = w.Abuse ?? rec.WhoisAbuseContact;
                        Interlocked.Increment(ref _whoisEnriched);
                    }).ConfigureAwait(false);
                }

                if (prefs.EnableReputation)
                {
                    await Stage("reputation", async () =>
                    {
                        var lookup = await _providerHealth.LookupAsync("reputation",
                            token => EnrichWithReputationAsync(target, token), RemoteLookupBudget, ct).ConfigureAwait(false);
                        rec.ReputationEnrichmentStatus = lookup.Status.ToString();
                        var rep = lookup.Value;
                        if (rep is null) return;
                        rec.ReputationLookupIp = target;
                        rec.ReputationScore = rep.AbuseConfidenceScore;
                        rec.ReputationReports = rep.TotalReports;
                        if (DateTimeOffset.TryParse(rep.LastReportedAt, out var dto))
                            rec.ReputationLastSeen = dto.UtcDateTime;
                        rec.ReputationIsMalicious = IsMalicious(rec.ReputationScore);
                        Interlocked.Increment(ref _reputationEnriched);
                    }).ConfigureAwait(false);
                }

                await Stage("vpn-proxy", async () =>
                {
                    var context = new VpnContext
                    {
                        Ip = target,
                        AllowRdap = prefs.EnableWhois,
                        DstPort = string.Equals(target, rec.Source, StringComparison.Ordinal)
                            ? rec.SourcePort : rec.DestinationPort,
                        Protocol = rec.Protocol,
                        Ja4h = rec.HttpJa4h,
                        Ja4x = rec.TlsJa4x,
                        Sni = rec.Sni,
                        ProcessName = rec.ProcessName,
                        AbuseScore = rec.ReputationScore
                    };
                    var lookup = await _providerHealth.LookupAsync("vpn-proxy",
                        token => ClassifyVpnAsync(context, token), RemoteLookupBudget, ct).ConfigureAwait(false);
                    rec.VpnEnrichmentStatus = lookup.Status.ToString();
                    var classification = lookup.Value;
                    if (classification is null) return;

                    rec.IsVpn = classification.IsVpn;
                    rec.IsProxy = classification.IsProxy;
                    rec.NetworkType = classification.NetworkType;
                    rec.VpnClassificationIp = target;
                    rec.VpnClassificationConfidence = classification.Confidence;
                    rec.VpnPortHint = classification.VpnPortHint;
                }).ConfigureAwait(false);

            }, () => EvaluateRules(rec), ex => Report("pipeline", ex), ct);
        }

        private async Task<VpnProxyResult?> ClassifyVpnAsync(VpnContext context, CancellationToken ct)
        {
            await _vpnLimiter.WaitAsync(ct).ConfigureAwait(false);
            try { return await VpnProxyResolver.CheckAsync(context, ct).ConfigureAwait(false); }
            finally { _vpnLimiter.Release(); }
        }

        private void EnrichGeo(TrafficRecord rec)
        {
            lock (_geoIpLock)
            {
                if (!string.IsNullOrWhiteSpace(rec.Source)
                    && IsEnrichablePublicIp(rec.Source))
                {
                    var sourceGeo = _geoIpService.Lookup(rec.Source);
                    if (sourceGeo is not null)
                        TrafficRecordGeoEnrichment.ApplySource(rec, sourceGeo);
                }

                if (!string.IsNullOrWhiteSpace(rec.Destination)
                    && IsEnrichablePublicIp(rec.Destination))
                {
                    var destinationGeo = _geoIpService.Lookup(rec.Destination);
                    if (destinationGeo is not null)
                        TrafficRecordGeoEnrichment.ApplyDestination(rec, destinationGeo);
                }
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
            var lookup = await _providerHealth.LookupAsync("reputation",
                token => EnrichWithReputationAsync(ip, token), RemoteLookupBudget, ct).ConfigureAwait(false);
            if (ct.IsCancellationRequested) return;
            rec.ReputationEnrichmentStatus = lookup.Status.ToString();
            var rep = lookup.Value;
            if (rep is null) return;

            rec.ReputationLookupIp = ip;
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
            {
                _providerHealth.RecordCacheHit("whois");
                return cached.Value;
            }

            var lazy = _whoisInflight.GetOrAdd(ip, _ =>
                new Lazy<Task<WhoisInfo?>>(async () =>
                {
                    await _whoisLimiter.WaitAsync(ct).ConfigureAwait(false);
                    try
                    {
                        var raw = await WhoisResolver.LookupRawAsync(ip, ct).ConfigureAwait(false);
                        ct.ThrowIfCancellationRequested();
                        if (string.IsNullOrWhiteSpace(raw)) return null;
                        if (raw.StartsWith("WHOIS lookup failed:", StringComparison.OrdinalIgnoreCase))
                            throw new InvalidOperationException("RDAP lookup failed");

                        var info = new WhoisInfo
                        {
                            Asn = WhoisResolver.GetASN(raw),
                            Org = WhoisResolver.GetOrganization(raw) ?? WhoisResolver.GetRegistrar(raw),
                            CountryCode = WhoisResolver.GetCountry(raw),
                            Registrar = WhoisResolver.GetRegistrar(raw),
                            Abuse = WhoisResolver.GetAbuseContact(raw)
                        };
                        if (string.IsNullOrWhiteSpace(info.Asn) && string.IsNullOrWhiteSpace(info.Org)
                            && string.IsNullOrWhiteSpace(info.CountryCode) && string.IsNullOrWhiteSpace(info.Registrar)
                            && string.IsNullOrWhiteSpace(info.Abuse)) return null;
                        _whoisCache[ip] = CacheEntry<WhoisInfo>.From(info, WhoisTtl);
                        return info;
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
            {
                _providerHealth.RecordCacheHit("reputation");
                return cached.Value;
            }

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
                        ct.ThrowIfCancellationRequested();
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
                device.Filter = LanCaptureDiscovery.ComposeFilter(_currentFilter, _activeLanHost);
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
            => EndpointIpEnrichment.Classify(ip) == "Public";

        private static string? GetWhoisTarget(TrafficRecord record)
        {
            bool srcPublic = IsEnrichablePublicIp(record.Source ?? string.Empty);
            bool dstPublic = IsEnrichablePublicIp(record.Destination ?? string.Empty);
            if (srcPublic && dstPublic)
                return record.DstIsLocalHost == true && record.SrcIsLocalHost != true
                    ? record.Source : record.Destination;
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
            UiBatchesDelivered = Interlocked.Read(ref _uiBatchesDelivered),
            UiBatchLastDurationMs = Interlocked.Read(ref _uiBatchLastDurationMs),
            UiBatchMaxDurationMs = Interlocked.Read(ref _uiBatchMaxDurationMs),
            RuleEventsRaised = Interlocked.Read(ref _ruleEventsRaised),
            WhoisEnriched = Interlocked.Read(ref _whoisEnriched),
            ReputationEnriched = Interlocked.Read(ref _reputationEnriched),
            EnrichmentFallbacks = Interlocked.Read(ref _enrichmentFallbacks),
            WhoisCacheSize = _whoisCache.Count,
            ReputationCacheSize = _reputationCache.Count,
            EnrichmentQueueDepth = _enrichmentChannel.Reader.CanCount ? _enrichmentChannel.Reader.Count : null,
            EnrichmentProviders = _providerHealth.Snapshot()
        };

        public CaptureFlowSnapshot GetCaptureFlowSnapshot()
        {
            bool running;
            lock (_lifecycleLock) running = _runCts is { IsCancellationRequested: false };

            var started = Interlocked.Read(ref _captureStartedTicks);
            var lastCaptured = Interlocked.Read(ref _lastCapturedTicks);
            var lastDisplayed = Interlocked.Read(ref _lastUiDeliveredTicks);
            var captured = Math.Max(0, Interlocked.Read(ref _packetsCaptured) - Interlocked.Read(ref _capturedAtStart));
            var displayed = Math.Max(0, Interlocked.Read(ref _uiRecordsDelivered) - Interlocked.Read(ref _deliveredAtStart));
            var dropped = Math.Max(0, Interlocked.Read(ref _packetsDroppedByQueue) - Interlocked.Read(ref _droppedAtStart));
            var assessment = CaptureFlowHealth.Assess(running && started != 0,
                ToUtcOffset(started) ?? DateTimeOffset.UtcNow, captured, displayed, dropped,
                ToUtcOffset(lastCaptured), ToUtcOffset(lastDisplayed), DateTimeOffset.UtcNow);
            return new CaptureFlowSnapshot(assessment.State, captured, displayed, dropped, assessment.Reason);
        }

        public PerformanceCounterSnapshot GetPerformanceCounterSnapshot()
        {
            var flow = GetCaptureFlowSnapshot();
            return PerformanceCounterSnapshot.Capture(flow.Captured, flow.Displayed, flow.Dropped);
        }

        private static DateTimeOffset? ToUtcOffset(long ticks)
            => ticks > 0 ? new DateTimeOffset(new DateTime(ticks, DateTimeKind.Utc)) : null;

        public sealed record CaptureFlowSnapshot(CaptureFlowState State, long Captured, long Displayed, long Dropped, string Reason);

        public CaptureSourceHealth GetCaptureSourceHealth()
        {
            lock (_lifecycleLock)
            {
                if (_captureSource is EtwCapture etw)
                    return new CaptureSourceHealth("ETW", etw.IsRunning,
                        etw.EventsObserved, etw.EventsPublished, etw.EventsDropped, etw.LastError);

                if (_device != null)
                    return new CaptureSourceHealth("Npcap", _runCts is { IsCancellationRequested: false },
                        Math.Max(0, Interlocked.Read(ref _packetsCaptured) - Interlocked.Read(ref _capturedAtStart)),
                        Math.Max(0, Interlocked.Read(ref _packetsParsedOk) - Interlocked.Read(ref _parsedAtStart)),
                        Math.Max(0, Interlocked.Read(ref _packetsParseErrors) - Interlocked.Read(ref _parseErrorsAtStart)),
                        null);
            }

            return new CaptureSourceHealth("Capture source", false, 0, 0, 0, LastCaptureError);
        }

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
            // Keep the per-session flow diagnostics aligned with the reset counters.
            Interlocked.Exchange(ref _uiRecordsDelivered, 0);
            Interlocked.Exchange(ref _capturedAtStart, 0);
            Interlocked.Exchange(ref _deliveredAtStart, 0);
            Interlocked.Exchange(ref _droppedAtStart, 0);
            Interlocked.Exchange(ref _parsedAtStart, 0);
            Interlocked.Exchange(ref _parseErrorsAtStart, 0);
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
            public long UiBatchesDelivered { get; init; }
            public long UiBatchLastDurationMs { get; init; }
            public long UiBatchMaxDurationMs { get; init; }
            public long RuleEventsRaised { get; init; }
            public long WhoisEnriched { get; init; }
            public long ReputationEnriched { get; init; }
            public long EnrichmentFallbacks { get; init; }
            public int WhoisCacheSize { get; init; }
            public int ReputationCacheSize { get; init; }
            public int? EnrichmentQueueDepth { get; init; }
            // Lifetime counters for this capture service, independent of packet-stat resets.
            public IReadOnlyDictionary<string, EnrichmentProviderSnapshot> EnrichmentProviders { get; init; }
                = new Dictionary<string, EnrichmentProviderSnapshot>();
        }
    }
}
