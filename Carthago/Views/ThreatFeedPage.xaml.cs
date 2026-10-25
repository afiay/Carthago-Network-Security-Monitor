// SPDX-License-Identifier: MIT
// File: Views/ThreatFeedPage.xaml.cs
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Carthago.Analytics.Models;
using Carthago.Models;
using Carthago.Services;
using Carthago.Sinks;

namespace Carthago.Views
{
    public partial class ThreatFeedPage : Page, IResponsiveLayoutAware
    {
        private const int PageSize = 6;

        private readonly SinkHost _host;
        private readonly ObservableCollection<DetectionEvent> _detections;
        private readonly Dispatcher _ui;
        private readonly ThreatFeedVm _vm;
        private readonly Action? _openRawTraffic;
        private readonly Action? _openRawDetections;
        private readonly Action? _openIncidentQueue;
        private List<ThreatMatchVm> _filtered = new();

        public void ApplyResponsiveLayout(ResponsiveLayoutMode mode)
        {
            ResponsiveLayout.ApplyAdaptiveColumns(
                mode,
                new[] { PrimaryWorkspaceQueueColumn, PrimaryWorkspaceDetailColumn },
                new[] { PrimaryWorkspaceTopRow, PrimaryWorkspaceBottomRow },
                new FrameworkElement[] { QueuePanel, InvestigationPanel },
                new[] { 0.44, 0.56 },
                14);

            ResponsiveLayout.ApplyAdaptiveColumns(
                mode,
                new[] { SupportingWorkspaceFirstColumn, SupportingWorkspaceSecondColumn, SupportingWorkspaceThirdColumn },
                new[] { SupportingWorkspaceFirstRow, SupportingWorkspaceSecondRow, SupportingWorkspaceThirdRow },
                new FrameworkElement[] { FeedSourcesPanel, IndicatorTypesPanel, FeedHealthPanel },
                new[] { 1.0, 1.0, 1.12 },
                10);
        }

        public ThreatFeedPage(SinkHost sinkHost, ObservableCollection<DetectionEvent> detections)
            : this(sinkHost, detections, null, null, null)
        {
        }

        public ThreatFeedPage(
            SinkHost sinkHost,
            ObservableCollection<DetectionEvent> detections,
            Action? openRawTraffic,
            Action? openRawDetections,
            Action? openIncidentQueue)
        {
            InitializeComponent();
            ResponsiveLayout.ApplyWhenLoaded(this, ApplyResponsiveLayout);

            _host = sinkHost ?? throw new ArgumentNullException(nameof(sinkHost));
            _detections = detections ?? throw new ArgumentNullException(nameof(detections));
            _openRawTraffic = openRawTraffic;
            _openRawDetections = openRawDetections;
            _openIncidentQueue = openIncidentQueue;
            _ui = Dispatcher;
            _vm = new ThreatFeedVm();
            DataContext = _vm;

            var analytics = _host.Analytics;
            analytics.IncidentCreated += OnIncidentChanged;
            analytics.IncidentUpdated += OnIncidentChanged;
            analytics.AnomalyObserved += OnAnomalyObserved;
            analytics.StateReset += OnStateReset;
            _detections.CollectionChanged += DetectionsChanged;

            Unloaded += (_, __) =>
            {
                analytics.IncidentCreated -= OnIncidentChanged;
                analytics.IncidentUpdated -= OnIncidentChanged;
                analytics.AnomalyObserved -= OnAnomalyObserved;
                analytics.StateReset -= OnStateReset;
                _detections.CollectionChanged -= DetectionsChanged;
            };

            ThreatMatchesList.SelectionChanged += (_, __) =>
            {
                _vm.Selected = ThreatMatchesList.SelectedItem as ThreatMatchVm;
                UpdateSelectionState();
            };

            SeverityFilter.SelectionChanged += (_, __) =>
            {
                _vm.CurrentPage = 1;
                ApplyFilter();
            };

            SourceFilter.SelectionChanged += (_, __) =>
            {
                _vm.CurrentPage = 1;
                ApplyFilter();
            };

            LoadInitialMatches();
        }

        private void LoadInitialMatches()
        {
            RefreshWorkspace();
            ApplyFilter(keepSelection: false);
        }

        private void DetectionsChanged(object? sender, NotifyCollectionChangedEventArgs e)
            => _ui.BeginInvoke(new Action(() => RefreshWorkspace(_vm.Selected?.Key)));

        private void OnIncidentChanged(Incident incident)
            => _ui.BeginInvoke(new Action(() => RefreshWorkspace(_vm.Selected?.Key)));

        private void OnAnomalyObserved(AnomalySignal anomaly)
            => _ui.BeginInvoke(new Action(() => RefreshWorkspace(_vm.Selected?.Key)));

        private void OnStateReset()
            => _ui.BeginInvoke(new Action(LoadInitialMatches));

        private void RefreshWorkspace(string? selectedKey = null)
        {
            var now = DateTime.UtcNow;
            var incidents = _host.Analytics.GetRecentIncidents(250).ToArray();
            var anomalies = _host.Analytics.GetRecentAnomalies(300).ToArray();
            var merged = new Dictionary<string, ThreatMatchVm>(StringComparer.OrdinalIgnoreCase);

            foreach (var detection in _detections.OrderByDescending(item => item.Timestamp).Take(900))
            {
                var match = ThreatMatchVm.FromDetection(detection, FindRelatedIncident(detection, incidents));
                if (!match.IsThreatRelevant)
                    continue;

                MergeOrAdd(merged, match);
            }

            var snapshot = ThreatFeedWorkspaceProjectionService.Build(incidents, anomalies, now);
            foreach (var projection in snapshot.Matches)
                MergeOrAdd(merged, ThreatMatchVm.FromProjection(projection));

            var ordered = merged.Values
                .OrderByDescending(item => SeverityRank(item.Severity))
                .ThenByDescending(item => item.ScoreValue)
                .ThenByDescending(item => item.ConfidenceValue)
                .ThenByDescending(item => item.LastSeenUtc)
                .ToArray();

            ReplaceCollection(_vm.All, ordered);
            RefreshSummaries(snapshot);
            ApplyFilter(selectedKey);
        }

        private static void MergeOrAdd(IDictionary<string, ThreatMatchVm> target, ThreatMatchVm next)
        {
            if (target.TryGetValue(next.Key, out var existing))
            {
                existing.Merge(next);
                return;
            }

            target[next.Key] = next;
        }

        private Incident? FindRelatedIncident(DetectionEvent detection, IReadOnlyList<Incident> incidents)
        {
            var source = detection.SourceIp ?? string.Empty;
            var destination = detection.DestinationIp ?? detection.DestinationHost ?? string.Empty;

            return incidents.FirstOrDefault(incident =>
                (!string.IsNullOrWhiteSpace(source)
                 && string.Equals(incident.PrimarySourceIp, source, StringComparison.OrdinalIgnoreCase))
                || (!string.IsNullOrWhiteSpace(destination)
                    && (string.Equals(incident.PrimaryDestinationIp, destination, StringComparison.OrdinalIgnoreCase)
                        || string.Equals(incident.PrimaryDestinationHost, destination, StringComparison.OrdinalIgnoreCase)))
                || incident.RelatedEvents.Any(evt =>
                    string.Equals(evt.RuleId, detection.RuleId, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(evt.Description, detection.Description, StringComparison.OrdinalIgnoreCase)));
        }

        private void RefreshSummaries(ThreatFeedWorkspaceSnapshot snapshot)
        {
            var all = _vm.All.ToArray();

            ReplaceCollection(_vm.Kpis, new[]
            {
                new ThreatKpiVm("Active Feed Matches", all.Length.ToString(), $"{CountRecent(all, TimeSpan.FromMinutes(15))} in 15m", "Indicators currently matched in local evidence.", ResolveBrush("SeverityCriticalBrush"), "!"),
                new ThreatKpiVm("High Confidence IOCs", all.Count(item => item.ConfidenceValue >= 80).ToString(), $"{all.Count(item => item.SeverityRank >= 3)} severe", "Indicators ranked high confidence or greater.", ResolveBrush("SeverityHighBrush"), "IOC"),
                new ThreatKpiVm("Blocked / Suppressed", snapshot.SuppressedCount.ToString(), "Policy-backed only", "Suppression seen in related incidents.", ResolveBrush("AccentBrush"), "B"),
                new ThreatKpiVm("New Feed Indicators (24h)", all.Count(item => item.FirstSeenUtc >= DateTime.UtcNow.AddHours(-24)).ToString(), $"{CountRecent(all, TimeSpan.FromHours(1))} in 1h", "Unique recent IOC observations.", ResolveBrush("AccentAltBrush"), "+"),
                new ThreatKpiVm("Feed Health", snapshot.FeedHealthText, snapshot.FeedHealthDetail, "Threat feed service state and indicator availability.", ResolveBrush("OkBrush"), "OK")
            });

            ReplaceCollection(_vm.TopFeedSources,
                all.SelectMany(item => item.FeedSourceParts)
                    .GroupBy(source => source, StringComparer.OrdinalIgnoreCase)
                    .OrderByDescending(group => group.Count())
                    .ThenBy(group => group.Key)
                    .Take(5)
                    .Select(group => new ThreatSummaryVm(
                        group.Key,
                        group.Count().ToString(),
                        $"{group.Count()} active",
                        ResolveSummaryBrush(group.Key, all.Where(item => item.FeedSourceParts.Any(part => string.Equals(part, group.Key, StringComparison.OrdinalIgnoreCase)))))));

            ReplaceCollection(_vm.RecentIocTypes,
                all.GroupBy(item => item.IndicatorType, StringComparer.OrdinalIgnoreCase)
                    .OrderByDescending(group => group.Count())
                    .ThenBy(group => group.Key)
                    .Take(6)
                    .Select(group => new ThreatSummaryVm(
                        group.Key,
                        group.Count().ToString(),
                        $"{group.Count(item => item.FirstSeenUtc >= DateTime.UtcNow.AddHours(-24))} in 24h",
                        ResolveSummaryBrush(group.Key, group))));

            if (_vm.TopFeedSources.Count == 0)
                _vm.TopFeedSources.Add(new ThreatSummaryVm("No feed matches", "0", "Waiting for matches", ResolveBrush("TextMutedBrush")));

            if (_vm.RecentIocTypes.Count == 0)
                _vm.RecentIocTypes.Add(new ThreatSummaryVm("No IOC types", "0", "Waiting for matches", ResolveBrush("TextMutedBrush")));

            _vm.FooterText = all.Length == 0
                ? "No threat feed matches yet"
                : $"Threat intelligence surface is showing {all.Length} match(es) from live evidence.";
        }

        private void ApplyFilter(string? selectedKey = null, bool keepSelection = true)
        {
            if (!keepSelection)
                selectedKey = null;

            var severity = (SeverityFilter.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "All severities";
            var source = (SourceFilter.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "All feed sources";
            var search = SearchBox.Text?.Trim() ?? string.Empty;

            _filtered = _vm.All
                .Where(item => PassesFilter(item, severity, source, search))
                .OrderByDescending(item => item.SeverityRank)
                .ThenByDescending(item => item.ScoreValue)
                .ThenByDescending(item => item.ConfidenceValue)
                .ThenByDescending(item => item.LastSeenUtc)
                .ToList();

            UpdatePagination(selectedKey);
            UpdateEmptyState();
        }

        private static bool PassesFilter(ThreatMatchVm item, string severity, string source, string search)
        {
            if (!severity.StartsWith("All", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(item.Severity, severity, StringComparison.OrdinalIgnoreCase))
                return false;

            if (!source.StartsWith("All", StringComparison.OrdinalIgnoreCase)
                && !item.FeedSource.Contains(source, StringComparison.OrdinalIgnoreCase)
                && !item.FeedContext.Contains(source, StringComparison.OrdinalIgnoreCase))
                return false;

            if (string.IsNullOrWhiteSpace(search))
                return true;

            return item.Title.Contains(search, StringComparison.OrdinalIgnoreCase)
                   || item.Indicator.Contains(search, StringComparison.OrdinalIgnoreCase)
                   || item.FeedSource.Contains(search, StringComparison.OrdinalIgnoreCase)
                   || item.Classification.Contains(search, StringComparison.OrdinalIgnoreCase)
                   || item.RelatedHost.Contains(search, StringComparison.OrdinalIgnoreCase)
                   || item.RelatedIncidentTitle.Contains(search, StringComparison.OrdinalIgnoreCase)
                   || item.Tags.Any(tag => tag.Contains(search, StringComparison.OrdinalIgnoreCase))
                   || item.RelatedRules.Any(rule => rule.Contains(search, StringComparison.OrdinalIgnoreCase));
        }

        private void UpdatePagination(string? selectedKey)
        {
            _vm.TotalFilteredCount = _filtered.Count;
            _vm.TotalPages = Math.Max(1, (int)Math.Ceiling(Math.Max(_filtered.Count, 1) / (double)PageSize));

            if (!string.IsNullOrWhiteSpace(selectedKey))
            {
                var index = _filtered.FindIndex(item => string.Equals(item.Key, selectedKey, StringComparison.OrdinalIgnoreCase));
                if (index >= 0)
                    _vm.CurrentPage = (index / PageSize) + 1;
            }

            if (_vm.CurrentPage < 1)
                _vm.CurrentPage = 1;
            if (_vm.CurrentPage > _vm.TotalPages)
                _vm.CurrentPage = _vm.TotalPages;

            RefreshPageChips();
            RefreshVisibleMatches(selectedKey);
        }

        private void RefreshPageChips()
        {
            _vm.PageNumbers.Clear();
            if (_vm.TotalFilteredCount == 0)
                return;

            var start = Math.Max(1, _vm.CurrentPage - 2);
            var end = Math.Min(_vm.TotalPages, start + 4);
            start = Math.Max(1, end - 4);

            for (var page = start; page <= end; page++)
            {
                _vm.PageNumbers.Add(new ThreatPageChipVm
                {
                    PageNumber = page,
                    Label = page.ToString(),
                    IsCurrent = page == _vm.CurrentPage
                });
            }
        }

        private void RefreshVisibleMatches(string? selectedKey)
        {
            var items = _filtered
                .Skip((_vm.CurrentPage - 1) * PageSize)
                .Take(PageSize)
                .ToArray();

            ReplaceCollection(_vm.VisibleMatches, items);

            if (_vm.TotalFilteredCount == 0)
            {
                _vm.PageSummary = "Showing 0-0 of 0 matches";
                _vm.Selected = null;
                ThreatMatchesList.SelectedItem = null;
                UpdateSelectionState();
                return;
            }

            var start = ((_vm.CurrentPage - 1) * PageSize) + 1;
            var end = Math.Min(_vm.TotalFilteredCount, start + items.Length - 1);
            _vm.PageSummary = $"Showing {start}-{end} of {_vm.TotalFilteredCount} matches";

            var selected = !string.IsNullOrWhiteSpace(selectedKey)
                ? items.FirstOrDefault(item => string.Equals(item.Key, selectedKey, StringComparison.OrdinalIgnoreCase))
                : null;
            selected ??= items.FirstOrDefault();

            _vm.Selected = selected;
            ThreatMatchesList.SelectedItem = selected;
            UpdateSelectionState();
        }

        private void UpdateSelectionState()
        {
            var hasSelection = _vm.Selected != null;
            InvestigationBody.Visibility = hasSelection ? Visibility.Visible : Visibility.Collapsed;
            DetailsEmptyState.Visibility = hasSelection ? Visibility.Collapsed : Visibility.Visible;
        }

        private void UpdateEmptyState()
        {
            var hasRows = _vm.VisibleMatches.Count > 0;
            ThreatMatchesList.Visibility = hasRows ? Visibility.Visible : Visibility.Collapsed;
            ThreatEmptyState.Visibility = hasRows ? Visibility.Collapsed : Visibility.Visible;
        }

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            _vm.CurrentPage = 1;
            ApplyFilter();
        }

        private void PreviousPage_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.CurrentPage <= 1)
                return;

            _vm.CurrentPage--;
            RefreshPageChips();
            RefreshVisibleMatches(_vm.Selected?.Key);
        }

        private void NextPage_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.CurrentPage >= _vm.TotalPages)
                return;

            _vm.CurrentPage++;
            RefreshPageChips();
            RefreshVisibleMatches(_vm.Selected?.Key);
        }

        private void PageNumber_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not FrameworkElement { DataContext: ThreatPageChipVm page })
                return;

            _vm.CurrentPage = page.PageNumber;
            RefreshPageChips();
            RefreshVisibleMatches(_vm.Selected?.Key);
        }

        private void ExportIoc_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null)
                return;

            Clipboard.SetText(JsonSerializer.Serialize(_vm.Selected.ToExportObject(), new JsonSerializerOptions { WriteIndented = true }));
        }

        private void InvestigateHost_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null)
                return;

            if (Window.GetWindow(this) is MainWindow window)
            {
                window.OpenHostIntegrityWorkspace();
                if (!string.IsNullOrWhiteSpace(_vm.Selected.RelatedHost) && !string.Equals(_vm.Selected.RelatedHost, "Unknown host", StringComparison.OrdinalIgnoreCase))
                    Clipboard.SetText(_vm.Selected.RelatedHost);
                return;
            }

            Clipboard.SetText(_vm.Selected.RelatedHost);
        }

        private void ViewRelatedIncident_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null)
                return;

            if (_vm.Selected.HasRelatedIncident && Window.GetWindow(this) is MainWindow window)
            {
                window.OpenIncidentWorkspace(_vm.Selected.RelatedIncidentId);
                return;
            }

            if (_openIncidentQueue != null)
            {
                _openIncidentQueue.Invoke();
                return;
            }

            Clipboard.SetText(_vm.Selected.RelatedIncidentTitle);
        }

        private void OpenRawTraffic_Click(object sender, RoutedEventArgs e)
        {
            if (_openRawTraffic != null)
            {
                _openRawTraffic.Invoke();
                return;
            }

            Clipboard.SetText("Open Raw Traffic from the sidebar to inspect packets and flows for the selected IOC.");
        }

        private void OpenRawDetections_Click(object sender, RoutedEventArgs e)
        {
            if (_openRawDetections != null)
            {
                _openRawDetections.Invoke();
                return;
            }

            Clipboard.SetText("Open Raw Detections from the sidebar to inspect detection events for the selected IOC.");
        }

        private void QueueRowMore_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not FrameworkElement { DataContext: ThreatMatchVm match })
                return;

            ThreatMatchesList.SelectedItem = match;
            _vm.Selected = match;
            UpdateSelectionState();
            OpenActionsMenu(sender as FrameworkElement);
        }

        private void MoreActions_Click(object sender, RoutedEventArgs e)
            => OpenActionsMenu(sender as FrameworkElement);

        private void OpenActionsMenu(FrameworkElement? target)
        {
            if (target == null || _vm.Selected == null)
                return;

            var menu = new ContextMenu();
            if (_vm.Selected.HasRelatedIncident)
                menu.Items.Add(BuildMenuItem("Open related incident", ViewRelatedIncident_Click));
            menu.Items.Add(BuildMenuItem("Investigate host", InvestigateHost_Click));
            menu.Items.Add(BuildMenuItem("Open raw detections", OpenRawDetections_Click));
            menu.Items.Add(BuildMenuItem("Open raw traffic", OpenRawTraffic_Click));
            menu.Items.Add(new Separator());
            menu.Items.Add(BuildMenuItem("Copy IOC JSON", ExportIoc_Click));
            target.ContextMenu = menu;
            menu.IsOpen = true;
        }

        private MenuItem BuildMenuItem(string label, RoutedEventHandler handler)
        {
            var item = new MenuItem { Header = label };
            item.Click += handler;
            return item;
        }

        private void Page_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Escape)
            {
                ThreatMatchesList.SelectedItem = null;
                _vm.Selected = null;
                UpdateSelectionState();
            }
        }

        private Brush ResolveBrush(string resourceKey)
            => Application.Current.TryFindResource(resourceKey) as Brush ?? Brushes.DodgerBlue;

        private Brush ResolveSummaryBrush(string key, IEnumerable<ThreatMatchVm> items)
        {
            var severity = HighestSeverity(items.Select(item => item.Severity));
            return ResolveBrush(severity switch
            {
                "Critical" => "SeverityCriticalBrush",
                "High" => "SeverityHighBrush",
                "Medium" => "SeverityMediumBrush",
                "Low" => "SeverityLowBrush",
                _ => "TextMutedBrush"
            });
        }

        private static int CountRecent(IEnumerable<ThreatMatchVm> items, TimeSpan window)
        {
            var cutoff = DateTime.UtcNow.Subtract(window);
            return items.Count(item => item.FirstSeenUtc >= cutoff);
        }

        private static string HighestSeverity(IEnumerable<string> severities)
            => severities.OrderByDescending(SeverityRank).FirstOrDefault() ?? "Low";

        private static int SeverityRank(string? severity)
            => severity?.ToLowerInvariant() switch
            {
                "critical" => 4,
                "high" => 3,
                "medium" => 2,
                "low" => 1,
                _ => 0
            };

        private static void ReplaceCollection<T>(ObservableCollection<T> target, IEnumerable<T> values)
        {
            target.Clear();
            foreach (var value in values)
                target.Add(value);
        }
    }

    public sealed class ThreatFeedVm : INotifyPropertyChanged
    {
        public ObservableCollection<ThreatMatchVm> All { get; } = new();
        public ObservableCollection<ThreatMatchVm> VisibleMatches { get; } = new();
        public ObservableCollection<ThreatKpiVm> Kpis { get; } = new();
        public ObservableCollection<ThreatSummaryVm> TopFeedSources { get; } = new();
        public ObservableCollection<ThreatSummaryVm> RecentIocTypes { get; } = new();
        public ObservableCollection<ThreatPageChipVm> PageNumbers { get; } = new();

        private ThreatMatchVm? _selected;
        public ThreatMatchVm? Selected
        {
            get => _selected;
            set { _selected = value; OnChanged(); }
        }

        private int _currentPage = 1;
        public int CurrentPage
        {
            get => _currentPage;
            set
            {
                _currentPage = value;
                OnChanged();
                OnChanged(nameof(HasPreviousPage));
                OnChanged(nameof(HasNextPage));
            }
        }

        private int _totalPages = 1;
        public int TotalPages
        {
            get => _totalPages;
            set
            {
                _totalPages = value;
                OnChanged();
                OnChanged(nameof(HasPreviousPage));
                OnChanged(nameof(HasNextPage));
            }
        }

        public bool HasPreviousPage => CurrentPage > 1;
        public bool HasNextPage => CurrentPage < TotalPages;

        private int _totalFilteredCount;
        public int TotalFilteredCount
        {
            get => _totalFilteredCount;
            set { _totalFilteredCount = value; OnChanged(); }
        }

        private string _pageSummary = "Showing 0-0 of 0 matches";
        public string PageSummary
        {
            get => _pageSummary;
            set { _pageSummary = value; OnChanged(); }
        }

        private string _footerText = "No threat feed matches yet";
        public string FooterText
        {
            get => _footerText;
            set { _footerText = value; OnChanged(); }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public sealed record ThreatKpiVm(string Title, string Value, string Delta, string Detail, Brush AccentBrush, string Glyph);

    public sealed record ThreatSummaryVm(string Name, string Count, string TrendText, Brush AccentBrush);

    public sealed class ThreatPageChipVm : INotifyPropertyChanged
    {
        private int _pageNumber;
        private string _label = "1";
        private bool _isCurrent;

        public int PageNumber
        {
            get => _pageNumber;
            set { _pageNumber = value; OnChanged(); }
        }

        public string Label
        {
            get => _label;
            set { _label = value; OnChanged(); }
        }

        public bool IsCurrent
        {
            get => _isCurrent;
            set { _isCurrent = value; OnChanged(); }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public sealed class ThreatMatchVm : INotifyPropertyChanged
    {
        public string Key { get; private set; } = string.Empty;
        public string Id { get; private set; } = string.Empty;
        public string Title { get; private set; } = "Threat match";
        public string Summary { get; private set; } = "Threat-linked evidence was observed.";
        public string Indicator { get; private set; } = "Unknown indicator";
        public string IndicatorType { get; private set; } = "Indicator";
        public string FeedSource { get; private set; } = "Threat / reputation analytics";
        public IReadOnlyList<string> FeedSourceParts => FeedSource.Split(" • ", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        public string FeedContext { get; private set; } = "Threat intelligence";
        public string Classification { get; private set; } = "Threat match";
        public string Severity { get; private set; } = "Low";
        public string SeverityUpper => Severity.ToUpperInvariant();
        public int SeverityRank => Severity.ToLowerInvariant() switch
        {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0
        };
        public int ScoreValue { get; private set; }
        public string Score => ScoreValue.ToString();
        public int ConfidenceValue { get; private set; }
        public string ConfidenceText => ConfidenceValue == 0 ? "Unverified" : ConfidenceValue >= 85 ? "High" : ConfidenceValue >= 60 ? "Medium" : "Low";
        public string RelatedHost { get; private set; } = "Unknown host";
        public string RelatedIncidentTitle { get; private set; } = "No related incident";
        public string RelatedIncidentId { get; private set; } = string.Empty;
        public bool HasRelatedIncident => !string.IsNullOrWhiteSpace(RelatedIncidentId);
        public DateTime FirstSeenUtc { get; private set; } = DateTime.UtcNow;
        public DateTime LastSeenUtc { get; private set; } = DateTime.UtcNow;
        public string FirstSeenLabel => FirstSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
        public string LastSeenLabel => LastSeenUtc.ToLocalTime().ToString("HH:mm:ss");
        public string FeedState { get; private set; } = "Observed";
        public bool CanBlockIndicator => false;
        public bool IsThreatRelevant { get; private set; }
        public ObservableCollection<string> Evidence { get; } = new();
        public ObservableCollection<string> Tags { get; } = new();
        public ObservableCollection<string> RelatedRules { get; } = new();

        public static ThreatMatchVm FromDetection(DetectionEvent detection, Incident? relatedIncident)
        {
            var vm = new ThreatMatchVm();
            vm.UpdateFromDetection(detection, relatedIncident);
            return vm;
        }

        public static ThreatMatchVm FromProjection(ThreatMatchProjection projection)
        {
            var vm = new ThreatMatchVm();
            vm.UpdateFromProjection(projection);
            return vm;
        }

        private void UpdateFromProjection(ThreatMatchProjection projection)
        {
            Id = projection.Id;
            Indicator = string.IsNullOrWhiteSpace(projection.Indicator) ? "Unknown indicator" : projection.Indicator;
            IndicatorType = string.IsNullOrWhiteSpace(projection.IndicatorKind) ? "Indicator" : projection.IndicatorKind;
            Title = string.IsNullOrWhiteSpace(projection.Title) ? "Threat match" : projection.Title;
            Summary = string.IsNullOrWhiteSpace(projection.Summary) ? "Threat-linked evidence was observed." : projection.Summary;
            FeedSource = string.IsNullOrWhiteSpace(projection.FeedSource) ? "Threat / reputation analytics" : projection.FeedSource;
            FeedContext = $"{FeedSource} • {projection.Classification}";
            Classification = string.IsNullOrWhiteSpace(projection.Classification) ? "Threat match" : projection.Classification;
            Severity = string.IsNullOrWhiteSpace(projection.Severity) ? "High" : projection.Severity;
            ScoreValue = Math.Clamp(projection.RiskScore, 0, 100);
            ConfidenceValue = Math.Clamp(projection.Confidence, 0, 100);
            RelatedHost = string.IsNullOrWhiteSpace(projection.RelatedHost) ? "Unknown host" : projection.RelatedHost;
            RelatedIncidentTitle = string.IsNullOrWhiteSpace(projection.RelatedIncidentTitle) ? "No related incident" : projection.RelatedIncidentTitle;
            RelatedIncidentId = projection.RelatedIncidentId ?? string.Empty;
            FirstSeenUtc = projection.FirstSeenUtc == default ? DateTime.UtcNow : projection.FirstSeenUtc.ToUniversalTime();
            LastSeenUtc = FirstSeenUtc;
            FeedState = string.IsNullOrWhiteSpace(projection.FeedState) ? "Observed" : projection.FeedState;
            IsThreatRelevant = true;
            Key = $"{IndicatorType}:{Indicator}:{Classification}".ToLowerInvariant();

            ReplaceCollection(Evidence, projection.Evidence);
            ReplaceCollection(Tags, projection.Tags);
            ReplaceCollection(RelatedRules, projection.RelatedRules);
            RaiseAll();
        }

        private void UpdateFromDetection(DetectionEvent detection, Incident? relatedIncident)
        {
            var description = detection.Description ?? string.Empty;
            var indicator = PickIndicator(detection);
            var threatMatch = TryGetThreatFeedMatch(indicator, detection);
            var classification = Classify(description, indicator, detection, threatMatch);
            var feed = threatMatch != null
                ? string.Join(" • ", threatMatch.Sources.Take(2))
                : PickFeedSource(description, detection);
            var severity = NormalizeSeverity(detection.Severity.ToString(), classification);
            var score = threatMatch != null
                ? Math.Max(ScoreFor(severity, classification, description), threatMatch.Confidence)
                : ScoreFor(severity, classification, description);

            IsThreatRelevant = IsRelevant(description, classification, detection);
            Id = detection.RuleId ?? Guid.NewGuid().ToString("N");
            Indicator = string.IsNullOrWhiteSpace(indicator) ? "Unknown indicator" : indicator;
            IndicatorType = threatMatch?.Kind.ToString() ?? DetectIndicatorType(Indicator, detection);
            Classification = classification;
            Severity = severity;
            ScoreValue = score;
            ConfidenceValue = Math.Clamp(threatMatch?.Confidence
                ?? (detection.ConfidenceScore > 0 ? (int)Math.Round(detection.ConfidenceScore * 100) : 0), 0, 100);
            FeedSource = string.IsNullOrWhiteSpace(feed) ? "Detection evidence" : feed;
            FeedContext = $"{FeedSource} • {classification}";
            RelatedHost = detection.SourceIp ?? "Unknown host";
            RelatedIncidentTitle = relatedIncident?.Title ?? "No related incident";
            RelatedIncidentId = relatedIncident?.Id ?? string.Empty;
            FirstSeenUtc = detection.Timestamp == default ? DateTime.UtcNow : detection.Timestamp.ToUniversalTime();
            LastSeenUtc = FirstSeenUtc;
            Title = BuildTitle(classification, IndicatorType);
            Summary = threatMatch != null
                ? "Observed traffic matched an external threat intelligence indicator."
                : "Rule-generated observation; external threat intelligence did not confirm the indicator.";
            FeedState = threatMatch == null ? "Observed" : "Matched";
            Key = $"{IndicatorType}:{Indicator}:{Classification}".ToLowerInvariant();

            ReplaceCollection(Evidence, BuildEvidence(detection, relatedIncident, classification, threatMatch));
            ReplaceCollection(Tags, BuildTags(classification, IndicatorType, feed, threatMatch));
            ReplaceCollection(RelatedRules, string.IsNullOrWhiteSpace(detection.RuleId)
                ? new[] { "No rule id" }
                : new[] { detection.RuleId });
            RaiseAll();
        }

        public void Merge(ThreatMatchVm next)
        {
            if (next.LastSeenUtc < LastSeenUtc && next.ScoreValue <= ScoreValue && next.ConfidenceValue <= ConfidenceValue)
                return;

            if (next.LastSeenUtc > LastSeenUtc)
                LastSeenUtc = next.LastSeenUtc;

            if (next.FirstSeenUtc < FirstSeenUtc)
                FirstSeenUtc = next.FirstSeenUtc;

            ScoreValue = Math.Max(ScoreValue, next.ScoreValue);
            ConfidenceValue = Math.Max(ConfidenceValue, next.ConfidenceValue);
            Severity = StrongerSeverity(Severity, next.Severity);
            FeedState = string.Equals(next.FeedState, "Matched", StringComparison.OrdinalIgnoreCase) ? next.FeedState : FeedState;

            if (!HasRelatedIncident && next.HasRelatedIncident)
            {
                RelatedIncidentId = next.RelatedIncidentId;
                RelatedIncidentTitle = next.RelatedIncidentTitle;
            }

            if (string.Equals(RelatedHost, "Unknown host", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(next.RelatedHost))
                RelatedHost = next.RelatedHost;

            foreach (var item in next.Evidence.Where(value => !Evidence.Contains(value)))
                Evidence.Add(item);
            foreach (var item in next.Tags.Where(value => !Tags.Contains(value)))
                Tags.Add(item);
            foreach (var item in next.RelatedRules.Where(value => !RelatedRules.Contains(value)))
                RelatedRules.Add(item);

            RaiseAll();
        }

        public object ToExportObject() => new
        {
            Title,
            Indicator,
            IndicatorType,
            Classification,
            FeedSource,
            FeedContext,
            Severity,
            ScoreValue,
            ConfidenceValue,
            RelatedHost,
            RelatedIncidentTitle,
            RelatedIncidentId,
            FirstSeenUtc,
            LastSeenUtc,
            FeedState,
            Evidence = Evidence.ToArray(),
            Tags = Tags.ToArray(),
            RelatedRules = RelatedRules.ToArray()
        };

        private static string PickIndicator(DetectionEvent detection)
            => detection.DestinationIp
               ?? detection.DestinationHost
               ?? detection.Asn
               ?? detection.Ja4
               ?? detection.Hassh
               ?? detection.SourceIp
               ?? detection.RuleId
               ?? "Unknown indicator";

        private static string DetectIndicatorType(string value, DetectionEvent detection)
        {
            if (!string.IsNullOrWhiteSpace(detection.Asn))
                return "ASN";
            if (!string.IsNullOrWhiteSpace(detection.Ja4) || !string.IsNullOrWhiteSpace(detection.Hassh))
                return "Hash";
            if (value.Contains('.') && value.Any(char.IsLetter))
                return "Domain";
            if (value.Contains(':'))
                return "IPv6";
            if (value.Count(ch => ch == '.') == 3)
                return "IPv4";
            if (value.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                return "URL";
            return "Indicator";
        }

        private static MatchInfo? TryGetThreatFeedMatch(string indicator, DetectionEvent detection)
        {
            foreach (var candidate in new[]
                     {
                         indicator,
                         detection.DestinationHost,
                         detection.DestinationIp,
                         detection.SourceIp,
                         detection.Asn,
                         detection.Ja4,
                         detection.Hassh
                     })
            {
                if (!string.IsNullOrWhiteSpace(candidate) && ThreatFeedService.TryMatch(candidate, out var match))
                    return match;
            }

            return null;
        }

        private static string Classify(string description, string indicator, DetectionEvent detection, MatchInfo? threatMatch)
        {
            if (threatMatch == null && string.Equals(detection.RuleId, "R006", StringComparison.OrdinalIgnoreCase))
                return "DNS Activity";

            var text = $"{description} {indicator} {detection.RuleId} {string.Join(" ", threatMatch?.Tags ?? Array.Empty<string>())}".ToLowerInvariant();

            if (threatMatch != null && text.Contains("urlhaus", StringComparison.OrdinalIgnoreCase))
                return "Malware / Trojan";
            if (text.Contains("c2") || text.Contains("command") || text.Contains("control") || text.Contains("botnet"))
                return "Command & Control";
            if (text.Contains("tor"))
                return "Privacy / Evasion";
            if (text.Contains("phish") || text.Contains("credential"))
                return "Credential Theft";
            if (text.Contains("malware") || text.Contains("trojan") || text.Contains("hash"))
                return "Malware / Trojan";
            if (text.Contains("reputation") || text.Contains("abuse") || text.Contains("blacklist") || text.Contains("ioc"))
                return "Reputation Match";
            if (!string.IsNullOrWhiteSpace(detection.Country) || !string.IsNullOrWhiteSpace(detection.Asn))
                return "Infrastructure Risk";
            return "Suspicious Indicator";
        }

        private static string PickFeedSource(string description, DetectionEvent detection)
        {
            var text = $"{description} {detection.RuleId}".ToLowerInvariant();
            if (text.Contains("abuse"))
                return "AbuseIPDB";
            if (text.Contains("tor"))
                return "Tor Exit Feed";
            if (text.Contains("ioc"))
                return "Local IOC List";
            if (text.Contains("threat"))
                return "Threat feed";
            if (!string.IsNullOrWhiteSpace(detection.Asn))
                return "Reputation Feed";
            return "Detection evidence";
        }

        private static string NormalizeSeverity(string severity, string classification)
        {
            if (string.Equals(severity, "Critical", StringComparison.OrdinalIgnoreCase))
                return "Critical";
            if (string.Equals(severity, "High", StringComparison.OrdinalIgnoreCase))
                return "High";
            if (classification is "Command & Control" or "Malware / Trojan" or "Credential Theft")
                return "High";
            if (string.Equals(severity, "Medium", StringComparison.OrdinalIgnoreCase))
                return "Medium";
            return "Low";
        }

        private static int ScoreFor(string severity, string classification, string description)
        {
            var baseScore = severity.ToLowerInvariant() switch
            {
                "critical" => 96,
                "high" => 84,
                "medium" => 63,
                "low" => 34,
                _ => 25
            };

            if (classification.Contains("Command", StringComparison.OrdinalIgnoreCase))
                baseScore = Math.Max(baseScore, 92);
            if (description.Contains("multiple", StringComparison.OrdinalIgnoreCase))
                baseScore += 3;

            return Math.Clamp(baseScore, 0, 100);
        }

        private static bool IsRelevant(string description, string classification, DetectionEvent detection)
        {
            if (string.Equals(classification, "DNS Activity", StringComparison.OrdinalIgnoreCase)
                && detection.Severity < SeverityLevel.High)
                return false;

            if (detection.Severity is SeverityLevel.High or SeverityLevel.Critical)
                return true;

            var text = $"{description} {detection.RuleId} {detection.DestinationHost}".ToLowerInvariant();
            return text.Contains("reputation")
                   || text.Contains("abuse")
                   || text.Contains("ioc")
                   || text.Contains("threat")
                   || text.Contains("tor")
                   || text.Contains("malware")
                   || text.Contains("botnet")
                   || text.Contains("c2")
                   || text.Contains("command")
                   || text.Contains("phish")
                   || !string.Equals(classification, "Suspicious Indicator", StringComparison.OrdinalIgnoreCase);
        }

        private static string BuildTitle(string classification, string indicatorType)
            => classification switch
            {
                "DNS Activity" => "DNS activity observed",
                "Command & Control" => "Known C2 endpoint matched",
                "Credential Theft" => "Malicious domain observed",
                "Malware / Trojan" => "Known malware indicator detected",
                "Privacy / Evasion" => "Privacy or evasion endpoint contacted",
                "Infrastructure Risk" => $"Suspicious {indicatorType} destination",
                _ => "Threat indicator matched"
            };

        private static IEnumerable<string> BuildEvidence(DetectionEvent detection, Incident? incident, string classification, MatchInfo? threatMatch)
        {
            yield return threatMatch != null
                ? "Detection matched external threat-intelligence indicator evidence."
                : "Rule-generated observation; no external threat-feed match was confirmed.";
            if (threatMatch != null)
            {
                yield return $"Threat feed match: {threatMatch.Kind} {threatMatch.Value} with confidence {threatMatch.Confidence}.";
                if (threatMatch.Sources.Length > 0)
                    yield return $"Feed source: {string.Join(", ", threatMatch.Sources.Take(4))}.";
            }
            if (!string.IsNullOrWhiteSpace(detection.RuleId))
                yield return $"Rule {detection.RuleId} contributed to the match.";
            if (!string.IsNullOrWhiteSpace(detection.Description))
                yield return detection.Description;
            if (incident != null)
                yield return $"Related incident: {incident.Title}";
            if (!string.IsNullOrWhiteSpace(detection.Country) || !string.IsNullOrWhiteSpace(detection.Asn))
                yield return $"Enrichment: {detection.Country ?? "unknown country"} / {detection.Asn ?? "unknown ASN"}.";
            yield return $"Classification: {classification}.";
        }

        private static IEnumerable<string> BuildTags(string classification, string type, string feed, MatchInfo? threatMatch)
        {
            yield return type;
            yield return feed;
            if (threatMatch != null)
            {
                foreach (var source in threatMatch.Sources.Take(3))
                    yield return source;
                foreach (var tag in threatMatch.Tags.Take(4))
                    yield return tag;
            }
            foreach (var part in classification.Split('/', '&', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                yield return part;
            yield return threatMatch != null ? "Threat feed" : "Detection observation";
        }

        private static string StrongerSeverity(string a, string b)
        {
            static int Rank(string value) => value.ToLowerInvariant() switch
            {
                "critical" => 4,
                "high" => 3,
                "medium" => 2,
                "low" => 1,
                _ => 0
            };

            return Rank(b) > Rank(a) ? b : a;
        }

        private static void ReplaceCollection(ObservableCollection<string> target, IEnumerable<string> values)
        {
            target.Clear();
            foreach (var value in values.Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.OrdinalIgnoreCase))
                target.Add(value);
        }

        private void RaiseAll()
        {
            OnChanged(nameof(Key));
            OnChanged(nameof(Id));
            OnChanged(nameof(Title));
            OnChanged(nameof(Summary));
            OnChanged(nameof(Indicator));
            OnChanged(nameof(IndicatorType));
            OnChanged(nameof(FeedSource));
            OnChanged(nameof(FeedContext));
            OnChanged(nameof(Classification));
            OnChanged(nameof(Severity));
            OnChanged(nameof(SeverityUpper));
            OnChanged(nameof(SeverityRank));
            OnChanged(nameof(ScoreValue));
            OnChanged(nameof(Score));
            OnChanged(nameof(ConfidenceValue));
            OnChanged(nameof(ConfidenceText));
            OnChanged(nameof(RelatedHost));
            OnChanged(nameof(RelatedIncidentTitle));
            OnChanged(nameof(RelatedIncidentId));
            OnChanged(nameof(HasRelatedIncident));
            OnChanged(nameof(FirstSeenUtc));
            OnChanged(nameof(LastSeenUtc));
            OnChanged(nameof(FirstSeenLabel));
            OnChanged(nameof(LastSeenLabel));
            OnChanged(nameof(FeedState));
            OnChanged(nameof(CanBlockIndicator));
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
