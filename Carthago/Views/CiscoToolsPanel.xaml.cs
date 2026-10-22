// SPDX-License-Identifier: MIT
// File: Views/CiscoToolsPanel.xaml.cs

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using Carthago.Models;
using Carthago.Services.Cisco;
using Microsoft.Win32;

namespace Carthago.Views
{
    public partial class CiscoToolsPanel : UserControl, INotifyPropertyChanged
    {
        private const string StateFileName = "cisco-state.json";

        private readonly ObservableCollection<CiscoDevice> _devices = new();
        private readonly ObservableCollection<CiscoSyslogEvent> _syslogEvents = new();
        private readonly ObservableCollection<CiscoLink> _links = new();

        private readonly ObservableCollection<CiscoIncident> _incidents = new();
        private readonly Dictionary<string, CiscoIncident> _incidentIndex = new();

        private readonly CiscoDiscoveryService _discoveryService = new();
        private readonly CiscoSshService _sshService = new();
        private CiscoSyslogListener? _listener;

        // rules engine
        private readonly IncidentRulesEngine _rules = new();

        // Whether to show only degraded devices (Warning / Critical)
        private bool _showOnlyDegradedDevices;

        // Selected device for the insight panel
        private CiscoDevice? _selectedDevice;

        // Per-device syslog view for the drill-down grid
        private readonly ListCollectionView _selectedDeviceEventsView;

        // Event history for per-device activity metrics
        private readonly Dictionary<CiscoDevice, List<DateTime>> _deviceEventHistory = new();

        // Syslog time window filter
        private SyslogTimeWindow _syslogTimeWindow = SyslogTimeWindow.All;

        private int _selectedDeviceEventsLast5Minutes;
        private int _selectedDeviceEventsLast60Minutes;

        public event PropertyChangedEventHandler? PropertyChanged;

        public ObservableCollection<CiscoDevice> Devices => _devices;
        public ObservableCollection<CiscoSyslogEvent> SyslogEvents => _syslogEvents;
        public ObservableCollection<CiscoLink> Links => _links;
        public ObservableCollection<CiscoIncident> Incidents => _incidents;

        public CiscoDevice? SelectedDevice
        {
            get => _selectedDevice;
            // IMPORTANT: public setter so WPF TwoWay bindings can write to it
            set
            {
                if (!ReferenceEquals(_selectedDevice, value))
                {
                    _selectedDevice = value;
                    OnPropertyChanged();
                    _selectedDeviceEventsView.Refresh();
                    UpdateSelectedDeviceStats();
                }
            }
        }

        public ICollectionView SelectedDeviceEventsView => _selectedDeviceEventsView;

        public int SelectedDeviceEventsLast5Minutes
        {
            get => _selectedDeviceEventsLast5Minutes;
            private set
            {
                if (_selectedDeviceEventsLast5Minutes != value)
                {
                    _selectedDeviceEventsLast5Minutes = value;
                    OnPropertyChanged();
                }
            }
        }

        public int SelectedDeviceEventsLast60Minutes
        {
            get => _selectedDeviceEventsLast60Minutes;
            private set
            {
                if (_selectedDeviceEventsLast60Minutes != value)
                {
                    _selectedDeviceEventsLast60Minutes = value;
                    OnPropertyChanged();
                }
            }
        }

        public CiscoToolsPanel()
        {
            var assemblyName = typeof(CiscoToolsPanel).Assembly.GetName().Name;
            var resourceUri = new Uri($"/{assemblyName};component/Views/CiscoToolsPanel.xaml", UriKind.Relative);
            Application.LoadComponent(this, resourceUri);

            DataContext = this;

            var devicesView = CollectionViewSource.GetDefaultView(_devices);
            if (devicesView != null)
                devicesView.Filter = DeviceFilter;

            _selectedDeviceEventsView = new ListCollectionView(_syslogEvents);
            _selectedDeviceEventsView.Filter = SelectedDeviceEventsFilter;

            LoadStateSafe();

            UpdateDevicesSummary();
            UpdateSyslogSummary();
            UpdateRulesCounter();
        }

        protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

        // ------------- helper lookups -------------
        private TextBox? GetTextBox(string name) => FindName(name) as TextBox;
        private ComboBox? GetComboBox(string name) => FindName(name) as ComboBox;
        private Button? GetButton(string name) => FindName(name) as Button;
        private DataGrid? GetDataGrid(string name) => FindName(name) as DataGrid;
        private TextBlock? GetTextBlock(string name) => FindName(name) as TextBlock;
        private CheckBox? GetCheckBox(string name) => FindName(name) as CheckBox;

        // ------------- device filter/sort -------------
        private bool DeviceFilter(object? item)
        {
            if (item is not CiscoDevice device) return false;
            if (!_showOnlyDegradedDevices) return true;
            var state = device.HealthState ?? string.Empty;
            return !state.Equals("Good", StringComparison.OrdinalIgnoreCase);
        }

        private void OnlyDegradedDevicesCheckBox_Changed(object sender, RoutedEventArgs e)
        {
            _showOnlyDegradedDevices = (sender as CheckBox)?.IsChecked == true;
            CollectionViewSource.GetDefaultView(_devices)?.Refresh();
        }

        private void SortByWorstHealth_Click(object sender, RoutedEventArgs e)
        {
            var grid = GetDataGrid("DevicesGrid");
            if (grid == null) return;
            var view = CollectionViewSource.GetDefaultView(grid.ItemsSource);
            if (view == null) return;

            using (view.DeferRefresh())
            {
                view.SortDescriptions.Clear();
                view.SortDescriptions.Add(new SortDescription(nameof(CiscoDevice.HealthScore), ListSortDirection.Ascending));
                view.SortDescriptions.Add(new SortDescription(nameof(CiscoDevice.Name), ListSortDirection.Ascending));
            }
        }

        // ------------- per-device drilldown -------------
        private bool SelectedDeviceEventsFilter(object? item)
        {
            if (item is not CiscoSyslogEvent ev) return false;
            if (_selectedDevice == null) return false;

            var selName = _selectedDevice.Name;
            var selHost = _selectedDevice.Host;

            var evKey = !string.IsNullOrWhiteSpace(ev.DeviceName)
                ? ev.DeviceName
                : (!string.IsNullOrWhiteSpace(ev.DeviceOrHost) ? ev.DeviceOrHost : ev.Host);

            if (!string.IsNullOrWhiteSpace(evKey))
            {
                if (!string.IsNullOrWhiteSpace(selName) &&
                    string.Equals(evKey, selName, StringComparison.OrdinalIgnoreCase)) return true;

                if (!string.IsNullOrWhiteSpace(selHost) &&
                    string.Equals(evKey, selHost, StringComparison.OrdinalIgnoreCase)) return true;
            }

            if (!string.IsNullOrWhiteSpace(selHost) &&
                !string.IsNullOrWhiteSpace(ev.Host) &&
                string.Equals(ev.Host, selHost, StringComparison.OrdinalIgnoreCase)) return true;

            return false;
        }

        private void TrackDeviceEventForStats(CiscoDevice device, DateTime timestampUtc)
        {
            if (!_deviceEventHistory.TryGetValue(device, out var list))
            {
                list = new List<DateTime>();
                _deviceEventHistory[device] = list;
            }

            list.Add(timestampUtc);

            // Trim older than 60m
            var cutoff = DateTime.UtcNow.AddMinutes(-60);
            int i = 0;
            while (i < list.Count && list[i] < cutoff) i++;
            if (i > 0) list.RemoveRange(0, i);

            if (ReferenceEquals(device, _selectedDevice))
                UpdateSelectedDeviceStats();
        }

        private void UpdateSelectedDeviceStats()
        {
            if (_selectedDevice == null || !_deviceEventHistory.TryGetValue(_selectedDevice, out var list) || list.Count == 0)
            {
                SelectedDeviceEventsLast5Minutes = 0;
                SelectedDeviceEventsLast60Minutes = 0;
                return;
            }

            var now = DateTime.UtcNow;
            var c5 = list.Count(ts => ts >= now.AddMinutes(-5));
            var c60 = list.Count(ts => ts >= now.AddMinutes(-60));
            SelectedDeviceEventsLast5Minutes = c5;
            SelectedDeviceEventsLast60Minutes = c60;
        }

        // ------------- device mgmt -------------

        private void AddDevice_Click(object sender, RoutedEventArgs e)
        {
            var nameBox = GetTextBox("NewDeviceNameBox");
            var hostBox = GetTextBox("NewDeviceHostBox");
            var roleBox = GetTextBox("NewDeviceRoleBox");
            var portBox = GetTextBox("NewDevicePortBox");

            if (nameBox == null || hostBox == null || roleBox == null || portBox == null)
            {
                MessageBox.Show("Device form controls not found in XAML.", "Cisco Tools",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            var name = nameBox.Text.Trim();
            var host = hostBox.Text.Trim();
            var role = roleBox.Text.Trim();
            var portText = portBox.Text.Trim();

            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(host))
            {
                MessageBox.Show("Name and Host/IP are required.", "Cisco Tools",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!int.TryParse(portText, out var port) || port <= 0 || port > 65535)
            {
                MessageBox.Show("Syslog port must be a valid TCP/UDP port (1-65535).",
                    "Cisco Tools", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var matches = _devices
                .Where(d =>
                    (!string.IsNullOrWhiteSpace(name) && d.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) ||
                    (!string.IsNullOrWhiteSpace(host) && d.Host.Equals(host, StringComparison.OrdinalIgnoreCase)))
                .ToList();

            if (matches.Count > 0)
            {
                var existing = matches[0];
                existing.Name = name;
                existing.Host = host;
                existing.Role = role;
                existing.SyslogPort = port;
                existing.IsEnabled = true;

                for (int j = 1; j < matches.Count; j++)
                {
                    _devices.Remove(matches[j]);
                    _deviceEventHistory.Remove(matches[j]);
                }
            }
            else
            {
                _devices.Add(new CiscoDevice
                {
                    Name = name,
                    Host = host,
                    Role = role,
                    SyslogPort = port,
                    IsEnabled = true
                });
            }

            var listenerPortBox = GetTextBox("ListenerPortBox");
            if (listenerPortBox != null)
                listenerPortBox.Text = port.ToString(CultureInfo.InvariantCulture);

            UpdateDevicesSummary();
        }

        private void ClearDeviceForm_Click(object sender, RoutedEventArgs e)
        {
            var nameBox = GetTextBox("NewDeviceNameBox");
            var hostBox = GetTextBox("NewDeviceHostBox");
            var roleBox = GetTextBox("NewDeviceRoleBox");
            var portBox = GetTextBox("NewDevicePortBox");

            if (nameBox != null) nameBox.Text = string.Empty;
            if (hostBox != null) hostBox.Text = string.Empty;
            if (roleBox != null) roleBox.Text = string.Empty;
            if (portBox != null) portBox.Text = "5514";
        }

        private void RemoveSelectedDevice_Click(object sender, RoutedEventArgs e)
        {
            var grid = GetDataGrid("DevicesGrid");
            if (grid?.SelectedItem is CiscoDevice device)
            {
                _devices.Remove(device);
                _links.RemoveWhere(l => ReferenceEquals(l.Local, device) || ReferenceEquals(l.Remote, device));
                _deviceEventHistory.Remove(device);
                if (ReferenceEquals(_selectedDevice, device)) SelectedDevice = null;
                UpdateDevicesSummary();
            }
        }

        private void DevicesGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (sender is not DataGrid grid) return;
            if (grid.SelectedItem is not CiscoDevice device) return;
            FocusLogsForDevice(device);
        }

        private void DevicesGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (sender is not DataGrid grid || grid.SelectedItem is not CiscoDevice device) return;

            var dlg = new CiscoCredentialsDialog(
                device.SshUsername,
                device.SshPassword,
                device.SshEnablePassword)
            { Owner = Window.GetWindow(this) };

            if (dlg.ShowDialog() == true)
            {
                device.SshUsername = dlg.Username;
                device.SshPassword = dlg.Password;
                device.SshEnablePassword = string.IsNullOrEmpty(dlg.EnablePassword) ? dlg.Password : dlg.EnablePassword;
            }
        }

        private void EditDeviceMenuItem_Click(object sender, RoutedEventArgs e)
        {
            var grid = GetDataGrid("DevicesGrid");
            if (grid?.SelectedItem is not CiscoDevice device)
            {
                MessageBox.Show("Select a device first.", "Cisco Tools",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dlg = new CiscoDeviceEditDialog(device) { Owner = Window.GetWindow(this) };
            if (dlg.ShowDialog() == true)
            {
                device.Name = dlg.DeviceName;
                device.Host = dlg.Host;
                device.Role = dlg.Role;
                device.SyslogPort = dlg.SyslogPort;
                device.IsEnabled = dlg.DeviceEnabled;

                var listenerPortBox = GetTextBox("ListenerPortBox");
                if (listenerPortBox != null)
                    listenerPortBox.Text = device.SyslogPort.ToString(CultureInfo.InvariantCulture);

                UpdateDevicesSummary();
            }
        }

        private void EditCredentialsMenuItem_Click(object sender, RoutedEventArgs e)
        {
            var grid = GetDataGrid("DevicesGrid");
            if (grid?.SelectedItem is not CiscoDevice device) return;

            var dlg = new CiscoCredentialsDialog(
                device.SshUsername,
                device.SshPassword,
                device.SshEnablePassword)
            { Owner = Window.GetWindow(this) };

            if (dlg.ShowDialog() == true)
            {
                device.SshUsername = dlg.Username;
                device.SshPassword = dlg.Password;
                device.SshEnablePassword = string.IsNullOrEmpty(dlg.EnablePassword) ? dlg.Password : dlg.EnablePassword;
            }
        }

        private async void ReloadDeviceMenuItem_Click(object sender, RoutedEventArgs e)
        {
            var grid = GetDataGrid("DevicesGrid");
            if (grid?.SelectedItem is not CiscoDevice device)
            {
                MessageBox.Show("Select a device first.", "Cisco Tools",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            if (string.IsNullOrWhiteSpace(device.Host))
            {
                MessageBox.Show("Device Host/IP is not set.", "Cisco Tools",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (string.IsNullOrWhiteSpace(device.SshUsername) || string.IsNullOrWhiteSpace(device.SshPassword))
            {
                var dlg = new CiscoCredentialsDialog(device.SshUsername, device.SshPassword, device.SshEnablePassword)
                { Owner = Window.GetWindow(this) };
                if (dlg.ShowDialog() != true) return;
                device.SshUsername = dlg.Username;
                device.SshPassword = dlg.Password;
                device.SshEnablePassword = string.IsNullOrEmpty(dlg.EnablePassword) ? dlg.Password : dlg.EnablePassword;
            }

            try
            {
                await _sshService.ReloadAsync(device, CancellationToken.None);
                MessageBox.Show($"Reload command sent to {device.Name}.", "Cisco Tools",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to reload {device.Name} ({device.Host}): {ex.Message}",
                    "Cisco Tools", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // ------------- analyzer launcher -------------
        private void OpenAnalyzer_Click(object sender, RoutedEventArgs e)
        {
            var win = new CiscoAnalyzerFlyout(_devices, _syslogEvents) { Owner = Window.GetWindow(this) };
            win.Show();
        }

        // ------------- listener + syslog -------------
        private void StartListener_Click(object sender, RoutedEventArgs e)
        {
            var portBox = GetTextBox("ListenerPortBox");
            if (portBox == null ||
                !int.TryParse(portBox.Text.Trim(), out var port) ||
                port <= 0 || port > 65535)
            {
                MessageBox.Show("Listener port must be a valid TCP/UDP port (1-65535).",
                    "Cisco Tools", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            StopListenerInternal();

            _listener = new CiscoSyslogListener(port);
            _listener.MessageReceived += OnSyslogMessageReceived;
            _listener.Start();

            var startButton = GetButton("StartListenerButton");
            var stopButton = GetButton("StopListenerButton");
            if (startButton != null) startButton.IsEnabled = false;
            if (stopButton != null) stopButton.IsEnabled = true;
        }

        private void StopListener_Click(object sender, RoutedEventArgs e) => StopListenerInternal();

        private void StopListenerInternal()
        {
            if (_listener != null)
            {
                _listener.MessageReceived -= OnSyslogMessageReceived;
                _listener.Dispose();
                _listener = null;
            }

            var startButton = GetButton("StartListenerButton");
            var stopButton = GetButton("StopListenerButton");
            if (startButton != null) startButton.IsEnabled = true;
            if (stopButton != null) stopButton.IsEnabled = false;
        }

        private void ClearSyslog_Click(object sender, RoutedEventArgs e)
        {
            _syslogEvents.Clear();
            _deviceEventHistory.Clear();
            _incidents.Clear();
            _incidentIndex.Clear();

            UpdateSyslogSummary();
            ApplySyslogFilter();
            UpdateSelectedDeviceStats();
        }

        private void OnSyslogMessageReceived(CiscoSyslogEvent evt)
        {
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.Invoke(() => OnSyslogMessageReceived(evt));
                return;
            }

            _syslogEvents.Insert(0, evt);
            const int maxEvents = 5000;
            if (_syslogEvents.Count > maxEvents)
                _syslogEvents.RemoveAt(_syslogEvents.Count - 1);

            var device = UpdateDeviceLastSeen(evt);

            if (device != null)
            {
                TrackDeviceEventForStats(device, evt.Timestamp);
                UpdateIncidents(device, evt);
            }

            UpdateSyslogSummary();
        }

        private void UserControl_Unloaded(object sender, RoutedEventArgs e)
        {
            StopListenerInternal();
            SaveStateSafe();
        }

        // ------------- syslog filter/summary -------------
        private void SyslogSearchBox_TextChanged(object sender, TextChangedEventArgs e) => ApplySyslogFilter();
        private void SyslogSeverityFilterBox_SelectionChanged(object sender, SelectionChangedEventArgs e) => ApplySyslogFilter();

        private void SyslogTimeWindowBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var combo = sender as ComboBox;
            if (combo?.SelectedItem is ComboBoxItem item)
            {
                var tag = item.Tag as string;
                _syslogTimeWindow = tag switch
                {
                    "5m" => SyslogTimeWindow.Last5Minutes,
                    "30m" => SyslogTimeWindow.Last30Minutes,
                    "2h" => SyslogTimeWindow.Last2Hours,
                    "24h" => SyslogTimeWindow.Last24Hours,
                    _ => SyslogTimeWindow.All
                };
                ApplySyslogFilter();
            }
        }

        private void SecurityFocus_Click(object sender, RoutedEventArgs e)
        {
            var severityCombo = GetComboBox("SyslogSeverityFilterBox");
            if (severityCombo != null) severityCombo.SelectedIndex = 3; // Error+
            var timeCombo = GetComboBox("SyslogTimeWindowBox");
            if (timeCombo != null) timeCombo.SelectedIndex = 3; // 2h
            var searchBox = GetTextBox("SyslogSearchBox");
            if (searchBox != null) searchBox.Text = "Security";
            ApplySyslogFilter();
        }

        private void SyslogFilterReset_Click(object sender, RoutedEventArgs e)
        {
            var searchBox = GetTextBox("SyslogSearchBox");
            var severityCombo = GetComboBox("SyslogSeverityFilterBox");
            var timeCombo = GetComboBox("SyslogTimeWindowBox");

            if (searchBox != null) searchBox.Text = string.Empty;
            if (severityCombo != null) severityCombo.SelectedIndex = 0;
            if (timeCombo != null) timeCombo.SelectedIndex = 0;
            _syslogTimeWindow = SyslogTimeWindow.All;
            ApplySyslogFilter();
        }

        private int? GetSeverityThreshold()
        {
            var combo = GetComboBox("SyslogSeverityFilterBox");
            if (combo?.SelectedItem is ComboBoxItem item)
            {
                var tag = item.Tag as string;
                if (!string.IsNullOrWhiteSpace(tag) && int.TryParse(tag, out var code))
                    return code;
            }
            return null;
        }

        private void ApplySyslogFilter()
        {
            var grid = GetDataGrid("SyslogGrid");
            if (grid == null) return;
            var view = CollectionViewSource.GetDefaultView(grid.ItemsSource);
            if (view == null) return;

            var searchBox = GetTextBox("SyslogSearchBox");
            string text = searchBox?.Text?.Trim().ToLowerInvariant() ?? "";

            int? threshold = GetSeverityThreshold();

            view.Filter = o =>
            {
                if (o is not CiscoSyslogEvent ev) return false;

                if (threshold.HasValue && ev.SeverityCode.HasValue)
                {
                    if (ev.SeverityCode.Value > threshold.Value) return false;
                }

                if (_syslogTimeWindow != SyslogTimeWindow.All)
                {
                    var age = DateTime.UtcNow - ev.Timestamp;
                    switch (_syslogTimeWindow)
                    {
                        case SyslogTimeWindow.Last5Minutes:
                            if (age > TimeSpan.FromMinutes(5)) return false;
                            break;
                        case SyslogTimeWindow.Last30Minutes:
                            if (age > TimeSpan.FromMinutes(30)) return false;
                            break;
                        case SyslogTimeWindow.Last2Hours:
                            if (age > TimeSpan.FromHours(2)) return false;
                            break;
                        case SyslogTimeWindow.Last24Hours:
                            if (age > TimeSpan.FromHours(24)) return false;
                            break;
                    }
                }

                if (!string.IsNullOrEmpty(text))
                {
                    var hay = $"{ev.DeviceOrHost} {ev.Host} {ev.CiscoCode} {ev.Category} {ev.ShortMessage}".ToLowerInvariant();
                    if (!hay.Contains(text)) return false;
                }

                return true;
            };

            view.Refresh();
        }

        private void UpdateDevicesSummary()
        {
            var textBlock = GetTextBlock("DevicesSummaryText");
            if (textBlock == null) return;

            int total = _devices.Count, good = 0, warn = 0, crit = 0;
            foreach (var d in _devices)
            {
                switch ((d.HealthState ?? "").ToLowerInvariant())
                {
                    case "good": good++; break;
                    case "warning": warn++; break;
                    case "critical": crit++; break;
                }
            }

            textBlock.Text = $"{total} devices  •  Good: {good}  •  Warning: {warn}  •  Critical: {crit}";
        }

        private void UpdateSyslogSummary()
        {
            var countText = GetTextBlock("SyslogCountText");
            if (countText != null) countText.Text = _syslogEvents.Count.ToString(CultureInfo.InvariantCulture);

            if (_syslogEvents.Count == 0)
            {
                var deviceCountText = GetTextBlock("SyslogDeviceCountText");
                if (deviceCountText != null) deviceCountText.Text = "0";
                var lastEventText = GetTextBlock("SyslogLastEventText");
                if (lastEventText != null) lastEventText.Text = "n/a";
                return;
            }

            var deviceCount = _syslogEvents
                .Select(e => string.IsNullOrEmpty(e.DeviceName) ? e.Host : e.DeviceName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();

            var deviceCountText2 = GetTextBlock("SyslogDeviceCountText");
            if (deviceCountText2 != null) deviceCountText2.Text = deviceCount.ToString(CultureInfo.InvariantCulture);

            var last = _syslogEvents[0];
            var lastEventText2 = GetTextBlock("SyslogLastEventText");
            if (lastEventText2 != null) lastEventText2.Text = $"{last.SeverityName} · {last.Category}";
        }

        // ------------- Device state + auto-discovery from syslog -------------
        private CiscoDevice? UpdateDeviceLastSeen(CiscoSyslogEvent evt)
        {
            var hostKey = evt.Host;
            var nameKey = evt.DeviceName;

            var device = _devices.FirstOrDefault(d =>
                (!string.IsNullOrEmpty(hostKey) && d.Host.Equals(hostKey, StringComparison.OrdinalIgnoreCase)) ||
                (!string.IsNullOrEmpty(nameKey) && d.Name.Equals(nameKey, StringComparison.OrdinalIgnoreCase)));

            if (device == null)
            {
                device = AutoCreateDeviceForEvent(evt);
                if (device == null) return null;
            }

            device.LastSeenUtc = evt.Timestamp;
            device.LastEventSeverityName = evt.SeverityName;
            device.LastEventCategory = evt.Category;
            device.LastEventSummary = evt.ShortMessage;

            TryUpdateDeviceIos(device, evt);
            UpdateDevicesSummary();

            return device;
        }

        private CiscoDevice? AutoCreateDeviceForEvent(CiscoSyslogEvent evt)
        {
            var hostKey = string.IsNullOrWhiteSpace(evt.Host) ? null : evt.Host;
            var nameKey = string.IsNullOrWhiteSpace(evt.DeviceName) ? null : evt.DeviceName;

            if (hostKey == null && nameKey == null)
                return null;

            string name = nameKey ?? hostKey!;
            string host = hostKey ?? nameKey!;

            int port = 5514;
            var listenerPortBox = GetTextBox("ListenerPortBox");
            if (listenerPortBox != null &&
                int.TryParse(listenerPortBox.Text.Trim(), out var p) &&
                p > 0 && p <= 65535)
            {
                port = p;
            }

            var device = new CiscoDevice
            {
                Name = name,
                Host = host,
                Role = "Discovered Cisco device",
                SyslogPort = port,
                IsEnabled = true
            };

            _devices.Add(device);
            UpdateDevicesSummary();
            return device;
        }

        private static void TryUpdateDeviceIos(CiscoDevice device, CiscoSyslogEvent evt)
        {
            var msg = evt.ShortMessage ?? string.Empty;
            if (!msg.Contains("Cisco IOS Software", StringComparison.OrdinalIgnoreCase) ||
                !msg.Contains("Version", StringComparison.OrdinalIgnoreCase)) return;

            string version = ExtractIosVersion(msg);
            if (string.IsNullOrEmpty(version)) return;

            device.IosVersion = version;
            device.IosVersionLastSeenUtc = evt.Timestamp;
            device.IosStatus = ComputeIosStatus(version);
        }

        private static string ExtractIosVersion(string message)
        {
            int verIndex = message.IndexOf("Version", StringComparison.OrdinalIgnoreCase);
            if (verIndex < 0) return string.Empty;
            string after = message[(verIndex + "Version".Length)..].TrimStart();
            int comma = after.IndexOf(',');
            string token = comma >= 0 ? after[..comma] : after;
            return token.Trim();
        }

        private static string ComputeIosStatus(string version)
        {
            if (string.IsNullOrWhiteSpace(version)) return "Unknown";
            var m = Regex.Match(version, @"(?<maj>\d+)\.(?<min>\d+)");
            if (!m.Success) return "Unknown";

            int maj = int.Parse(m.Groups["maj"].Value, CultureInfo.InvariantCulture);
            int min = int.Parse(m.Groups["min"].Value, CultureInfo.InvariantCulture);

            if (maj > 15 || (maj == 15 && min >= 3)) return "Up to date";
            return "Update recommended";
        }

        // ------------- topology discovery -------------
        private async void DiscoverTopology_Click(object sender, RoutedEventArgs e)
        {
            var snmpBox = GetTextBox("SnmpCommunityBox");
            string community = snmpBox?.Text?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(community))
            {
                MessageBox.Show("Specify an SNMP community string first.", "Cisco Tools",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (_devices.Count == 0)
            {
                MessageBox.Show("No seed devices. Add or auto-discover at least one Cisco device first.",
                    "Cisco Tools", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var discoverButton = GetButton("DiscoverTopologyButton");
            if (discoverButton != null) discoverButton.IsEnabled = false;

            try
            {
                foreach (var device in _devices.ToList())
                {
                    if (string.IsNullOrWhiteSpace(device.Host)) continue;

                    try
                    {
                        var neighbors = await _discoveryService
                            .DiscoverNeighborsAsync(device, community)
                            .ConfigureAwait(true);

                        MergeNeighbors(device, neighbors);
                    }
                    catch
                    {
                        // log in production
                    }
                }

                RecomputeTopologyLayout();
            }
            finally
            {
                if (discoverButton != null) discoverButton.IsEnabled = true;
            }
        }

        private void MergeNeighbors(CiscoDevice local, IReadOnlyList<CiscoNeighbor> neighbors)
        {
            foreach (var n in neighbors)
            {
                CiscoDevice? remote = _devices.FirstOrDefault(d =>
                    (!string.IsNullOrWhiteSpace(n.RemoteMgmtAddress) && d.Host.Equals(n.RemoteMgmtAddress, StringComparison.OrdinalIgnoreCase)) ||
                    (!string.IsNullOrWhiteSpace(n.RemoteSysName) && d.Name.Equals(n.RemoteSysName, StringComparison.OrdinalIgnoreCase)) ||
                    (!string.IsNullOrWhiteSpace(n.RemoteDeviceId) && d.Name.Equals(n.RemoteDeviceId, StringComparison.OrdinalIgnoreCase)));

                if (remote == null)
                {
                    string displayName =
                        !string.IsNullOrWhiteSpace(n.RemoteSysName) ? n.RemoteSysName :
                        !string.IsNullOrWhiteSpace(n.RemoteDeviceId) ? n.RemoteDeviceId :
                        !string.IsNullOrWhiteSpace(n.RemoteMgmtAddress) ? n.RemoteMgmtAddress :
                        "Remote";

                    string host =
                        !string.IsNullOrWhiteSpace(n.RemoteMgmtAddress) ? n.RemoteMgmtAddress : displayName;

                    remote = new CiscoDevice
                    {
                        Name = displayName,
                        Host = host,
                        Role = $"Discovered via {n.Protocol}",
                        SyslogPort = local.SyslogPort,
                        IsEnabled = true
                    };

                    _devices.Add(remote);
                }

                remote.LastSeenUtc = DateTime.UtcNow;
                remote.LastEventSeverityName = "Informational";
                remote.LastEventCategory = "Topology discovery";
                remote.LastEventSummary = $"Discovered via {n.Protocol} from {local.Name} ({n.LocalInterface})";

                bool exists = _links.Any(l =>
                    (ReferenceEquals(l.Local, local) && ReferenceEquals(l.Remote, remote)) ||
                    (ReferenceEquals(l.Local, remote) && ReferenceEquals(l.Remote, local)));

                if (!exists)
                {
                    _links.Add(new CiscoLink
                    {
                        Local = local,
                        Remote = remote,
                        Protocol = n.Protocol,
                        LocalInterface = n.LocalInterface,
                        RemoteInterface = n.RemoteInterface,
                        LastSeenUtc = DateTime.UtcNow
                    });
                }
            }

            UpdateDevicesSummary();
        }

        private void RecomputeTopologyLayout()
        {
            if (_devices.Count == 0) return;

            var neighbors = _devices.ToDictionary(d => d, _ => new HashSet<CiscoDevice>());
            foreach (var link in _links)
            {
                if (link.Local == null || link.Remote == null) continue;
                neighbors[link.Local].Add(link.Remote);
                neighbors[link.Remote].Add(link.Local);
            }

            CiscoDevice root = _devices[0];
            int bestDeg = -1;
            foreach (var kv in neighbors)
            {
                int deg = kv.Value.Count;
                if (deg > bestDeg) { bestDeg = deg; root = kv.Key; }
            }

            var depth = new Dictionary<CiscoDevice, int>();
            var layers = new Dictionary<int, List<CiscoDevice>>();
            var q = new Queue<CiscoDevice>();
            depth[root] = 0; q.Enqueue(root);

            while (q.Count > 0)
            {
                var d = q.Dequeue();
                int dep = depth[d];

                if (!layers.TryGetValue(dep, out var list)) { list = new List<CiscoDevice>(); layers[dep] = list; }
                list.Add(d);

                foreach (var nb in neighbors[d])
                {
                    if (depth.ContainsKey(nb)) continue;
                    depth[nb] = dep + 1;
                    q.Enqueue(nb);
                }
            }

            int maxLayer = layers.Count == 0 ? 0 : layers.Keys.Max();
            foreach (var d in _devices)
            {
                if (depth.ContainsKey(d)) continue;
                int layer = maxLayer + 1; maxLayer = layer;
                depth[d] = layer;
                layers[layer] = new List<CiscoDevice> { d };
            }

            double centerX = 260, centerY = 110, layerRadius = 60;
            foreach (var kv in layers)
            {
                int layer = kv.Key;
                var items = kv.Value;
                int count = items.Count;
                if (count == 0) continue;

                double radius = layerRadius * (layer + 1);
                for (int i = 0; i < count; i++)
                {
                    double angle = (2.0 * Math.PI * i) / count;
                    var d = items[i];
                    d.TopologyX = centerX + radius * Math.Cos(angle);
                    d.TopologyY = centerY + radius * Math.Sin(angle);
                }
            }
        }

        private void TopologyDevice_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            if (sender is not FrameworkElement fe) return;
            if (fe.DataContext is not CiscoDevice device) return;
            FocusLogsForDevice(device);
        }

        private void FocusLogsForDevice(CiscoDevice device)
        {
            SelectedDevice = device;

            var searchBox = GetTextBox("SyslogSearchBox");
            var grid = GetDataGrid("SyslogGrid");
            if (searchBox == null || grid == null) return;

            var key = !string.IsNullOrWhiteSpace(device.Name) ? device.Name : device.Host;
            if (string.IsNullOrWhiteSpace(key)) return;

            searchBox.Text = key;
            ApplySyslogFilter();

            var view = CollectionViewSource.GetDefaultView(grid.ItemsSource);
            var firstItem = view.Cast<object?>().FirstOrDefault();
            if (firstItem != null)
            {
                grid.SelectedItem = firstItem;
                grid.ScrollIntoView(firstItem);
                grid.Focus();
            }
        }

        // ------------- Incident engine + rules -------------
        private void UpdateIncidents(CiscoDevice device, CiscoSyslogEvent evt)
        {
            var deviceKey = !string.IsNullOrWhiteSpace(device.Name) ? device.Name : (device.Host ?? "Unknown");
            var code = evt.CiscoCode ?? string.Empty;
            var category = evt.Category ?? string.Empty;
            var severity = evt.SeverityName ?? string.Empty;
            var template = NormalizeMessageTemplate(evt.ShortMessage ?? string.Empty);
            var id = $"{deviceKey}|{code}|{category}|{template}";

            if (!_incidentIndex.TryGetValue(id, out var incident))
            {
                incident = new CiscoIncident
                {
                    Id = id,
                    DeviceLabel = deviceKey,
                    CiscoCode = string.IsNullOrEmpty(code) ? "(n/a)" : code,
                    Category = string.IsNullOrEmpty(category) ? "Uncategorised" : category,
                    SeverityName = severity,
                    FirstTimestampUtc = evt.Timestamp,
                    LastTimestampUtc = evt.Timestamp,
                    Count = 1,
                    ExampleMessage = evt.ShortMessage ?? string.Empty,
                    State = "Active"
                };
                _incidentIndex[id] = incident;
                _incidents.Insert(0, incident);

                if (GetCheckBox("AutoApplyRulesCheck")?.IsChecked == true)
                    ApplyRulesToIncident(incident, evt, device);
            }
            else
            {
                incident.LastTimestampUtc = evt.Timestamp;
                incident.Count++;
                if (IsMoreSevere(severity, incident.SeverityName))
                    incident.SeverityName = severity;

                if (!string.Equals(incident.State, "Active", StringComparison.OrdinalIgnoreCase))
                    incident.State = "Active";

                if (GetCheckBox("AutoApplyRulesCheck")?.IsChecked == true)
                    ApplyRulesToIncident(incident, evt, device);
            }

            PruneIncidents();
        }

        private void ApplyRulesToIncident(CiscoIncident inc, CiscoSyslogEvent ev, CiscoDevice device)
        {
            var facts = new IncidentFacts
            {
                DeviceLabel = inc.DeviceLabel,
                Category = inc.Category,
                CiscoCode = inc.CiscoCode,
                SeverityName = inc.SeverityName,
                ExampleMessage = inc.ExampleMessage,
                CountInWindow = (win) =>
                {
                    var cutoff = DateTime.UtcNow - win;
                    var key = !string.IsNullOrWhiteSpace(device.Name) ? device.Name : device.Host;
                    if (string.IsNullOrWhiteSpace(key)) return 0;
                    return _syslogEvents.Count(e =>
                        e.Timestamp >= cutoff &&
                        (e.DeviceName?.Equals(key, StringComparison.OrdinalIgnoreCase) == true ||
                         e.DeviceOrHost?.Equals(key, StringComparison.OrdinalIgnoreCase) == true ||
                         e.Host?.Equals(key, StringComparison.OrdinalIgnoreCase) == true));
                }
            };

            var ctx = new IncidentContext(
                addTag: tag => inc.AddTag(tag),
                setHint: hint => inc.SetHint(hint),
                setRunbook: url => inc.RunbookUrl = url,
                escalate: sev => inc.SeverityName = MaxSeverity(inc.SeverityName, sev),
                suppress: () => inc.Suppressed = true,
                assign: owners => inc.AssignOwners(owners)
            );

            _rules.ApplyRules(ctx, facts);
        }

        private void PruneIncidents()
        {
            var now = DateTime.UtcNow;
            var inactiveCutoff = now.AddMinutes(-30);

            foreach (var inc in _incidents)
            {
                if (inc.LastTimestampUtc < inactiveCutoff &&
                    !string.Equals(inc.State, "Dormant", StringComparison.OrdinalIgnoreCase))
                {
                    inc.State = "Dormant";
                }
            }

            const int maxIncidents = 200;
            if (_incidents.Count > maxIncidents)
            {
                for (int i = _incidents.Count - 1; i >= maxIncidents; i--)
                {
                    var inc = _incidents[i];
                    _incidents.RemoveAt(i);
                    _incidentIndex.Remove(inc.Id);
                }
            }
        }

        private void UpdateRulesCounter()
        {
            var t = GetTextBlock("RulesCountText");
            if (t != null) t.Text = _rules.Rules.Count.ToString(CultureInfo.InvariantCulture);
        }

        // ------------- rules toolbar handlers -------------
        private void LoadRules_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog
            {
                Filter = "Rules files (*.json;*.yaml;*.yml)|*.json;*.yaml;*.yml|JSON (*.json)|*.json|YAML (*.yaml;*.yml)|*.yaml;*.yml",
                Title = "Load rules"
            };
            if (dlg.ShowDialog() == true)
            {
                try
                {
                    int n = _rules.LoadFromFile(dlg.FileName);
                    UpdateRulesCounter();
                    MessageBox.Show($"Loaded {n} rule(s).", "Rules", MessageBoxButton.OK, MessageBoxImage.Information);

                    if (_incidents.Count > 0)
                        ApplyRulesToAll_Click(sender, e);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to load rules: {ex.Message}", "Rules", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ApplyRulesToAll_Click(object? sender, RoutedEventArgs e)
        {
            if (_rules.Rules.Count == 0)
            {
                MessageBox.Show("No rules loaded.", "Rules", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            foreach (var inc in _incidents)
            {
                var dev = _devices.FirstOrDefault(d =>
                    string.Equals(d.Name, inc.DeviceLabel, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(d.Host, inc.DeviceLabel, StringComparison.OrdinalIgnoreCase))
                    ?? new CiscoDevice { Name = inc.DeviceLabel, Host = inc.DeviceLabel };

                var facts = new IncidentFacts
                {
                    DeviceLabel = inc.DeviceLabel,
                    Category = inc.Category,
                    CiscoCode = inc.CiscoCode,
                    SeverityName = inc.SeverityName,
                    ExampleMessage = inc.ExampleMessage,
                    CountInWindow = (win) =>
                    {
                        var cutoff = DateTime.UtcNow - win;
                        var key = inc.DeviceLabel;
                        return _syslogEvents.Count(e =>
                            e.Timestamp >= cutoff &&
                            (e.DeviceName?.Equals(key, StringComparison.OrdinalIgnoreCase) == true ||
                             e.DeviceOrHost?.Equals(key, StringComparison.OrdinalIgnoreCase) == true ||
                             e.Host?.Equals(key, StringComparison.OrdinalIgnoreCase) == true));
                    }
                };

                var ctx = new IncidentContext(
                    addTag: tag => inc.AddTag(tag),
                    setHint: hint => inc.SetHint(hint),
                    setRunbook: url => inc.RunbookUrl = url,
                    escalate: sev => inc.SeverityName = MaxSeverity(inc.SeverityName, sev),
                    suppress: () => inc.Suppressed = true,
                    assign: owners => inc.AssignOwners(owners)
                );

                _rules.ApplyRules(ctx, facts);
            }
        }

        private void ApplyRulesToSelected_Click(object sender, RoutedEventArgs e)
        {
            var grid = GetDataGrid("IncidentsGrid");
            if (grid == null) return;
            var selected = grid.SelectedItems.Cast<CiscoIncident>().ToList();
            if (selected.Count == 0)
            {
                MessageBox.Show("No incidents selected.", "Rules", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            foreach (var inc in selected)
            {
                var dev = _devices.FirstOrDefault(d =>
                    string.Equals(d.Name, inc.DeviceLabel, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(d.Host, inc.DeviceLabel, StringComparison.OrdinalIgnoreCase))
                    ?? new CiscoDevice { Name = inc.DeviceLabel, Host = inc.DeviceLabel };

                var facts = new IncidentFacts
                {
                    DeviceLabel = inc.DeviceLabel,
                    Category = inc.Category,
                    CiscoCode = inc.CiscoCode,
                    SeverityName = inc.SeverityName,
                    ExampleMessage = inc.ExampleMessage,
                    CountInWindow = (win) =>
                    {
                        var cutoff = DateTime.UtcNow - win;
                        var key = inc.DeviceLabel;
                        return _syslogEvents.Count(e =>
                            e.Timestamp >= cutoff &&
                            (e.DeviceName?.Equals(key, StringComparison.OrdinalIgnoreCase) == true ||
                             e.DeviceOrHost?.Equals(key, StringComparison.OrdinalIgnoreCase) == true ||
                             e.Host?.Equals(key, StringComparison.OrdinalIgnoreCase) == true));
                    }
                };

                var ctx = new IncidentContext(
                    addTag: tag => inc.AddTag(tag),
                    setHint: hint => inc.SetHint(hint),
                    setRunbook: url => inc.RunbookUrl = url,
                    escalate: sev => inc.SeverityName = MaxSeverity(inc.SeverityName, sev),
                    suppress: () => inc.Suppressed = true,
                    assign: owners => inc.AssignOwners(owners)
                );

                _rules.ApplyRules(ctx, facts);
            }
        }

        // ------------- export bundle -------------
        private void ExportIncidents_Click(object sender, RoutedEventArgs e)
        {
            var grid = GetDataGrid("IncidentsGrid");
            var items = grid?.SelectedItems?.Count > 0
                ? grid!.SelectedItems.Cast<CiscoIncident>().ToList()
                : _incidents.ToList();

            if (items.Count == 0)
            {
                MessageBox.Show("No incidents to export.", "Export", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dlg = new SaveFileDialog
            {
                Filter = "Markdown (*.md)|*.md|JSON (*.json)|*.json",
                FileName = $"cisco-incidents-{DateTime.UtcNow:yyyyMMdd-HHmmss}.md",
                Title = "Export incidents"
            };
            if (dlg.ShowDialog() == true)
            {
                try
                {
                    if (Path.GetExtension(dlg.FileName).Equals(".json", StringComparison.OrdinalIgnoreCase))
                    {
                        File.WriteAllText(dlg.FileName, BuildIncidentsJson(items), Encoding.UTF8);
                    }
                    else
                    {
                        File.WriteAllText(dlg.FileName, BuildIncidentsMarkdown(items), Encoding.UTF8);
                    }
                    MessageBox.Show("Export complete.", "Export", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Export failed: {ex.Message}", "Export", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void CopyIncidentsMarkdown_Click(object sender, RoutedEventArgs e)
        {
            var grid = GetDataGrid("IncidentsGrid");
            var items = grid?.SelectedItems?.Count > 0
                ? grid!.SelectedItems.Cast<CiscoIncident>().ToList()
                : _incidents.ToList();

            if (items.Count == 0)
            {
                MessageBox.Show("No incidents to copy.", "Copy", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            Clipboard.SetText(BuildIncidentsMarkdown(items));
        }

        private void ExportSelectedIncidents_Click(object sender, RoutedEventArgs e)
        {
            var grid = GetDataGrid("IncidentsGrid");
            if (grid == null || grid.SelectedItems.Count == 0)
            {
                MessageBox.Show("Select incidents first.", "Export", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            ExportIncidents_Click(sender, e);
        }

        private void CopySelectedMarkdown_Click(object sender, RoutedEventArgs e)
        {
            var grid = GetDataGrid("IncidentsGrid");
            if (grid == null || grid.SelectedItems.Count == 0)
            {
                MessageBox.Show("Select incidents first.", "Copy", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            var items = grid.SelectedItems.Cast<CiscoIncident>().ToList();
            Clipboard.SetText(BuildIncidentsMarkdown(items));
        }

        private string BuildIncidentsJson(List<CiscoIncident> items)
        {
            var bundle = new
            {
                exportedUtc = DateTime.UtcNow,
                deviceSnapshot = Devices.Select(d => new
                {
                    d.Name,
                    d.Host,
                    d.Role,
                    d.IosVersion,
                    d.IosStatus,
                    d.HealthScore,
                    d.HealthState,
                    d.LastSeenUtc
                }).ToList(),
                incidents = items.Select(SerializeIncident).ToList()
            };

            return JsonSerializer.Serialize(bundle, new JsonSerializerOptions
            {
                WriteIndented = true,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            });
        }

        private static object SerializeIncident(CiscoIncident inc) => new
        {
            inc.Id,
            inc.State,
            inc.DeviceLabel,
            inc.CiscoCode,
            inc.Category,
            inc.SeverityName,
            inc.Count,
            inc.FirstTimestampUtc,
            inc.LastTimestampUtc,
            inc.ExampleMessage,
            Tags = inc.Tags.ToArray(),
            inc.RunbookUrl,
            inc.Hint,
            inc.Suppressed,
            Owners = inc.Owners.ToArray()
        };

        private string BuildIncidentsMarkdown(List<CiscoIncident> items)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"# Cisco Incident Bundle");
            sb.AppendLine();
            sb.AppendLine($"Exported (UTC): **{DateTime.UtcNow:u}**");
            sb.AppendLine();

            var bySeverity = items.GroupBy(i => (i.SeverityName ?? "Info").ToUpperInvariant())
                                  .OrderByDescending(g => SeverityRank(g.Key));
            sb.AppendLine("## Summary");
            foreach (var g in bySeverity)
                sb.AppendLine($"- **{g.Key}**: {g.Count()}");
            sb.AppendLine();

            sb.AppendLine("## Incidents");
            foreach (var inc in items)
            {
                sb.AppendLine($"### {inc.DeviceLabel} · {inc.Category} · {inc.CiscoCode}");
                sb.AppendLine($"- **State:** {inc.State}   ·   **Severity:** {inc.SeverityName}   ·   **Count:** {inc.Count}");
                sb.AppendLine($"- **First:** {inc.FirstTimestampUtc:u}   ·   **Last:** {inc.LastTimestampUtc:u}");
                if (inc.Tags.Count > 0) sb.AppendLine($"- **Tags:** {string.Join(", ", inc.Tags)}");
                if (inc.Owners.Count > 0) sb.AppendLine($"- **Owners:** {string.Join(", ", inc.Owners)}");
                if (!string.IsNullOrWhiteSpace(inc.RunbookUrl)) sb.AppendLine($"- **Runbook:** {inc.RunbookUrl}");
                if (!string.IsNullOrWhiteSpace(inc.Hint)) sb.AppendLine($"> {inc.Hint.Trim()}");
                if (inc.Suppressed) sb.AppendLine($"- _Suppressed by rule_");

                sb.AppendLine();
                sb.AppendLine("**Example message**");
                sb.AppendLine();
                sb.AppendLine("```");
                sb.AppendLine(inc.ExampleMessage ?? "");
                sb.AppendLine("```");
                sb.AppendLine();
            }

            sb.AppendLine("## Device snapshot");
            foreach (var d in _devices.OrderBy(x => x.Name))
            {
                sb.AppendLine($"- **{d.Name}** ({d.Host}) — {d.Role} · IOS: {d.IosVersion} ({d.IosStatus}) · Health: {d.HealthScore}% [{d.HealthState}] · Last seen: {d.LastSeenUtc:u}");
            }

            return sb.ToString();
        }

        private static int SeverityRank(string s) => (s ?? "").Trim().ToLowerInvariant() switch
        {
            "critical" => 3,
            "error" => 2,
            "warning" => 1,
            _ => 0
        };

        private static string MaxSeverity(string a, string b)
            => SeverityRank(a) >= SeverityRank(b) ? a : b;

        private static bool IsMoreSevere(string candidate, string current)
            => SeverityRank(candidate) > SeverityRank(current);

        private static string NormalizeMessageTemplate(string message)
        {
            string result = Regex.Replace(message ?? "", @"\b\d{1,3}(\.\d{1,3}){3}\b", "{ip}",
                RegexOptions.CultureInvariant);
            result = Regex.Replace(result, @"\d+", "{#}", RegexOptions.CultureInvariant);
            return result;
        }

        // ------------- persistence -------------
        private void LoadStateSafe() { try { LoadState(); } catch { } }
        private void SaveStateSafe() { try { SaveState(); } catch { } }

        private void LoadState()
        {
            var path = GetStateFilePath();
            if (!File.Exists(path)) return;

            var json = File.ReadAllText(path);
            var state = JsonSerializer.Deserialize<PersistedState>(json);
            if (state == null) return;

            _devices.Clear();
            _links.Clear();

            var deviceMap = new Dictionary<string, CiscoDevice>(StringComparer.OrdinalIgnoreCase);
            foreach (var d in state.Devices ?? new())
            {
                var dev = new CiscoDevice
                {
                    Name = d.Name ?? string.Empty,
                    Host = d.Host ?? string.Empty,
                    Role = d.Role ?? string.Empty,
                    SyslogPort = d.SyslogPort,
                    IsEnabled = d.IsEnabled,
                    IosVersion = d.IosVersion,
                    IosStatus = d.IosStatus ?? "Unknown",
                    // HealthScore / HealthState are computed by the CiscoDevice model; do not restore them here
                    TopologyX = d.TopologyX,
                    TopologyY = d.TopologyY,
                    LastSeenUtc = d.LastSeenUtc
                };
                _devices.Add(dev);
                var key = !string.IsNullOrWhiteSpace(dev.Host) ? dev.Host : dev.Name;
                if (!string.IsNullOrWhiteSpace(key)) deviceMap[key] = dev;
            }

            foreach (var l in state.Links ?? new())
            {
                if (string.IsNullOrWhiteSpace(l.LocalKey) || string.IsNullOrWhiteSpace(l.RemoteKey)) continue;
                if (!deviceMap.TryGetValue(l.LocalKey, out var local)) continue;
                if (!deviceMap.TryGetValue(l.RemoteKey, out var remote)) continue;

                _links.Add(new CiscoLink
                {
                    Local = local,
                    Remote = remote,
                    Protocol = l.Protocol ?? string.Empty,
                    LocalInterface = l.LocalInterface ?? string.Empty,
                    RemoteInterface = l.RemoteInterface ?? string.Empty,
                    LastSeenUtc = l.LastSeenUtc
                });
            }
        }

        private void SaveState()
        {
            var state = new PersistedState
            {
                Devices = _devices.Select(d => new PersistedDevice
                {
                    Name = d.Name,
                    Host = d.Host,
                    Role = d.Role,
                    SyslogPort = d.SyslogPort,
                    IsEnabled = d.IsEnabled,
                    IosVersion = d.IosVersion,
                    IosStatus = d.IosStatus,
                    HealthScore = d.HealthScore,
                    HealthState = d.HealthState,
                    TopologyX = d.TopologyX,
                    TopologyY = d.TopologyY,
                    LastSeenUtc = d.LastSeenUtc
                }).ToList(),
                Links = _links.Select(l => new PersistedLink
                {
                    LocalKey = GetDeviceKey(l.Local),
                    RemoteKey = GetDeviceKey(l.Remote),
                    Protocol = l.Protocol,
                    LocalInterface = l.LocalInterface,
                    RemoteInterface = l.RemoteInterface,
                    LastSeenUtc = l.LastSeenUtc
                }).ToList()
            };

            var path = GetStateFilePath();
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var json = JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path, json);
        }

        private static string GetStateFilePath()
        {
            var root = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var dir = Path.Combine(root, "Carthago");
            return Path.Combine(dir, StateFileName);
        }

        private static string GetDeviceKey(CiscoDevice? d)
            => d == null ? "" : (!string.IsNullOrWhiteSpace(d.Host) ? d.Host : d.Name ?? "");

        private sealed class PersistedState
        {
            public List<PersistedDevice> Devices { get; set; } = new();
            public List<PersistedLink> Links { get; set; } = new();
        }

        private sealed class PersistedDevice
        {
            public string? Name { get; set; }
            public string? Host { get; set; }
            public string? Role { get; set; }
            public int SyslogPort { get; set; }
            public bool IsEnabled { get; set; }
            public string? IosVersion { get; set; }
            public string? IosStatus { get; set; }
            public int HealthScore { get; set; }
            public string? HealthState { get; set; }
            public double TopologyX { get; set; }
            public double TopologyY { get; set; }
            public DateTime? LastSeenUtc { get; set; }
        }

        private sealed class PersistedLink
        {
            public string? LocalKey { get; set; }
            public string? RemoteKey { get; set; }
            public string? Protocol { get; set; }
            public string? LocalInterface { get; set; }
            public string? RemoteInterface { get; set; }
            public DateTime LastSeenUtc { get; set; }
        }

        private enum SyslogTimeWindow { All, Last5Minutes, Last30Minutes, Last2Hours, Last24Hours }
    }

    // ------- Topology link converter -------
    public sealed class LinkToGeometryConverter : IMultiValueConverter
    {
        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            if (values.Length != 4) return Geometry.Empty;
            if (values[0] is double ax && values[1] is double ay && values[2] is double bx && values[3] is double by)
            {
                var start = new Point(ax + 40, ay + 15);
                var end = new Point(bx + 40, by + 15);
                return new LineGeometry(start, end);
            }
            return Geometry.Empty;
        }
        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }

    // ------- Incident model (extended for rules/export) -------
    public sealed class CiscoIncident : INotifyPropertyChanged
    {
        private string _state = "Active";
        private string _severityName = string.Empty;
        private int _count;
        private bool _suppressed;

        public string Id { get; set; } = string.Empty;
        public string DeviceLabel { get; set; } = string.Empty;
        public string CiscoCode { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;

        public string SeverityName
        {
            get => _severityName;
            set { if (!string.Equals(_severityName, value, StringComparison.Ordinal)) { _severityName = value; OnPropertyChanged(nameof(SeverityName)); } }
        }

        public DateTime FirstTimestampUtc { get; set; }
        public DateTime LastTimestampUtc { get; set; }

        public int Count
        {
            get => _count;
            set { if (_count != value) { _count = value; OnPropertyChanged(nameof(Count)); } }
        }

        public string ExampleMessage { get; set; } = string.Empty;

        public string State
        {
            get => _state;
            set { if (!string.Equals(_state, value, StringComparison.Ordinal)) { _state = value; OnPropertyChanged(nameof(State)); } }
        }

        public ObservableCollection<string> Tags { get; } = new();
        public string TagsInline => string.Join(", ", Tags);

        public string? RunbookUrl { get; set; }
        public string? Hint { get; private set; }

        public bool Suppressed
        {
            get => _suppressed;
            set { if (_suppressed != value) { _suppressed = value; OnPropertyChanged(nameof(Suppressed)); } }
        }

        public ObservableCollection<string> Owners { get; } = new();

        public void AddTag(string tag)
        {
            if (string.IsNullOrWhiteSpace(tag)) return;
            if (!Tags.Any(t => string.Equals(t, tag, StringComparison.OrdinalIgnoreCase)))
                Tags.Add(tag);
            OnPropertyChanged(nameof(TagsInline));
        }

        public void SetHint(string hint)
        {
            if (string.IsNullOrWhiteSpace(hint)) return;
            Hint = hint;
            OnPropertyChanged(nameof(Hint));
        }

        public void AssignOwners(IEnumerable<string> owners)
        {
            foreach (var o in owners)
            {
                if (string.IsNullOrWhiteSpace(o)) continue;
                if (!Owners.Any(x => string.Equals(x, o, StringComparison.OrdinalIgnoreCase)))
                    Owners.Add(o);
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged(string propertyName) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    internal static class ObservableCollectionExtensions
    {
        public static void RemoveWhere<T>(this ObservableCollection<T> collection, Func<T, bool> predicate)
        {
            for (int i = collection.Count - 1; i >= 0; i--)
            {
                if (predicate(collection[i])) collection.RemoveAt(i);
            }
        }
    }
}
