// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Carthago.Analytics.Models;
using Carthago.Services;
using Carthago.Sinks;

namespace Carthago.Views
{
    public partial class IncidentQueuePage : Page, IResponsiveLayoutAware
    {
        private const int PageSize = 7;

        private readonly SinkHost _host;
        private readonly Dispatcher _ui;
        private readonly IncidentQueueVm _vm = new();
        private List<IncidentVm> _filtered = new();

        public void ApplyResponsiveLayout(ResponsiveLayoutMode mode)
        {
            ResponsiveLayout.ApplyAdaptiveColumns(
                mode,
                new[] { PrimaryWorkspaceQueueColumn, PrimaryWorkspaceDetailColumn },
                new[] { PrimaryWorkspaceTopRow, PrimaryWorkspaceBottomRow },
                new FrameworkElement[] { QueuePanel, InvestigationPanel },
                new[] { 0.46, 0.54 },
                14);

            ResponsiveLayout.ApplyAdaptiveColumns(
                mode,
                new[] { SupportingWorkspaceFirstColumn, SupportingWorkspaceSecondColumn, SupportingWorkspaceThirdColumn },
                new[] { SupportingWorkspaceFirstRow, SupportingWorkspaceSecondRow, SupportingWorkspaceThirdRow },
                new FrameworkElement[] { TimelinePanel, AffectedHostsPanel, ResponseChecklistPanel },
                new[] { 1.08, 1.05, 0.92 },
                10);
        }

        public IncidentQueuePage(SinkHost sinkHost)
        {
            InitializeComponent();
            ResponsiveLayout.ApplyWhenLoaded(this, ApplyResponsiveLayout);

            _host = sinkHost ?? throw new ArgumentNullException(nameof(sinkHost));
            _ui = Dispatcher;
            DataContext = _vm;

            var analytics = _host.Analytics;
            analytics.IncidentCreated += OnIncidentChanged;
            analytics.IncidentUpdated += OnIncidentChanged;
            analytics.StateReset += OnStateReset;

            Unloaded += (_, __) =>
            {
                analytics.IncidentCreated -= OnIncidentChanged;
                analytics.IncidentUpdated -= OnIncidentChanged;
                analytics.StateReset -= OnStateReset;
            };

            SeverityFilter.SelectionChanged += (_, __) =>
            {
                _vm.FilterSeverity = (SeverityFilter.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "All severities";
                ApplyFilter();
            };
            StatusFilter.SelectionChanged += (_, __) =>
            {
                _vm.FilterStatus = (StatusFilter.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "All statuses";
                ApplyFilter();
            };
            OwnerFilter.SelectionChanged += (_, __) =>
            {
                _vm.FilterOwner = (OwnerFilter.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "All owners";
                ApplyFilter();
            };
            SearchBox.TextChanged += (_, __) =>
            {
                _vm.Search = SearchBox.Text ?? string.Empty;
                ApplyFilter();
            };
            QueueList.SelectionChanged += (_, __) =>
            {
                _vm.Selected = QueueList.SelectedItem as IncidentVm;
                RefreshSelectedDetails();
            };

            LoadInitial();
        }

        private void LoadInitial()
        {
            _vm.All.Clear();
            foreach (var incident in _host.Analytics.GetRecentIncidents(300))
                UpsertIncident(incident);

            RefreshKpis();
            ApplyFilter(keepSelection: false);
        }

        private void OnStateReset()
            => _ui.BeginInvoke(new Action(LoadInitial));

        private void OnIncidentChanged(Incident incident)
            => _ui.BeginInvoke(new Action(() =>
            {
                UpsertIncident(incident);
                RefreshKpis();
                ApplyFilter();
                RestoreSelection(incident.Id);
            }));

        private void UpsertIncident(Incident incident)
        {
            var existing = _vm.All.FirstOrDefault(item => item.Id == incident.Id);
            if (existing == null)
            {
                _vm.All.Add(IncidentVm.From(incident));
                return;
            }

            existing.UpdateFrom(incident);
        }

        private void ApplyFilter(bool keepSelection = true)
        {
            var selectedId = keepSelection ? _vm.Selected?.Id : null;

            _filtered = _vm.All
                .Where(PassesFilter)
                .OrderBy(item => item.IsResolved)
                .ThenByDescending(item => item.RiskScore)
                .ThenByDescending(item => item.UpdatedUtc)
                .ToList();

            UpdatePagination(selectedId);
            UpdateEmptyState();
        }

        private bool PassesFilter(IncidentVm incident)
        {
            if (!string.Equals(_vm.FilterSeverity, "All severities", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(incident.Severity, _vm.FilterSeverity, StringComparison.OrdinalIgnoreCase))
                return false;

            if (!string.Equals(_vm.FilterStatus, "All statuses", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(incident.Status, _vm.FilterStatus, StringComparison.OrdinalIgnoreCase))
                return false;

            if (string.Equals(_vm.FilterOwner, "Unassigned", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(incident.OwnerLabel, "Unassigned", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(_vm.Search))
            {
                var q = _vm.Search.Trim();
                if (!(incident.Title.Contains(q, StringComparison.OrdinalIgnoreCase)
                      || incident.SourceLabel.Contains(q, StringComparison.OrdinalIgnoreCase)
                      || incident.DestinationLabel.Contains(q, StringComparison.OrdinalIgnoreCase)
                      || incident.Summary.Contains(q, StringComparison.OrdinalIgnoreCase)
                      || incident.Category.Contains(q, StringComparison.OrdinalIgnoreCase)
                      || incident.Evidence.Any(value => value.Contains(q, StringComparison.OrdinalIgnoreCase))
                      || incident.RiskReasons.Any(value => value.Contains(q, StringComparison.OrdinalIgnoreCase))
                      || incident.RuleIds.Any(value => value.Contains(q, StringComparison.OrdinalIgnoreCase))))
                {
                    return false;
                }
            }

            return true;
        }

        private void UpdatePagination(string? selectedId)
        {
            _vm.TotalFilteredCount = _filtered.Count;
            _vm.TotalPages = Math.Max(1, (int)Math.Ceiling(Math.Max(_filtered.Count, 1) / (double)PageSize));

            if (!string.IsNullOrWhiteSpace(selectedId))
            {
                var index = _filtered.FindIndex(item => string.Equals(item.Id, selectedId, StringComparison.OrdinalIgnoreCase));
                if (index >= 0)
                    _vm.CurrentPage = (index / PageSize) + 1;
            }

            if (_vm.CurrentPage > _vm.TotalPages)
                _vm.CurrentPage = _vm.TotalPages;
            if (_vm.CurrentPage < 1)
                _vm.CurrentPage = 1;

            RefreshPageChips();
            RefreshVisibleQueue(selectedId);
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
                _vm.PageNumbers.Add(new QueuePageChipVm
                {
                    PageNumber = page,
                    Label = page.ToString(),
                    IsCurrent = page == _vm.CurrentPage
                });
            }
        }

        private void RefreshVisibleQueue(string? selectedId)
        {
            var pageItems = _filtered
                .Skip((_vm.CurrentPage - 1) * PageSize)
                .Take(PageSize)
                .ToArray();

            ReplaceCollection(_vm.VisibleQueue, pageItems);

            if (_vm.TotalFilteredCount == 0)
            {
                _vm.PageSummary = "Showing 0-0 of 0 incidents";
                _vm.Selected = null;
                QueueList.SelectedItem = null;
                RefreshSelectedDetails();
                return;
            }

            var start = ((_vm.CurrentPage - 1) * PageSize) + 1;
            var end = Math.Min(_vm.TotalFilteredCount, start + pageItems.Length - 1);
            _vm.PageSummary = $"Showing {start}-{end} of {_vm.TotalFilteredCount} incidents";

            var match = !string.IsNullOrWhiteSpace(selectedId)
                ? pageItems.FirstOrDefault(item => string.Equals(item.Id, selectedId, StringComparison.OrdinalIgnoreCase))
                : null;

            match ??= pageItems.FirstOrDefault();

            _vm.Selected = match;
            QueueList.SelectedItem = match;
            RefreshSelectedDetails();
        }

        private void RefreshKpis()
        {
            var stats = IncidentQueueProjectionService.BuildStats(
                _vm.All.Select(item => item.ToModel()),
                DateTime.UtcNow);

            ReplaceCollection(_vm.Kpis, new[]
            {
                new QueueKpiVm("Active Incidents", stats.ActiveIncidents.ToString(), $"{stats.CriticalIncidents} critical open", "Correlated queue pressure", ResolveBrush("SeverityHighBrush"), "!"),
                new QueueKpiVm("Critical Incidents", stats.CriticalIncidents.ToString(), $"{stats.InInvestigation} under review", "Highest-priority workload", ResolveBrush("SeverityCriticalBrush"), "C"),
                new QueueKpiVm("New in 1h", stats.NewInHour.ToString(), "Fresh cases entering triage", "Recent incident inflow", ResolveBrush("AccentBrush"), "+"),
                new QueueKpiVm("In Investigation", stats.InInvestigation.ToString(), "Acknowledged or active", "Analyst-owned cases", ResolveBrush("SeverityMediumBrush"), "I"),
                new QueueKpiVm("Resolved Today", stats.ResolvedToday.ToString(), "Closed during the current day", "Completed workflow", ResolveBrush("OkBrush"), "OK")
            });

            _vm.QueueCountLabel = $"{_vm.All.Count} incidents";
            _vm.FooterSeveritySummary = BuildFooterSeveritySummary(_vm.All);
        }

        private void RefreshSelectedDetails()
        {
            var selected = _vm.Selected;
            _vm.SelectedOwnerLabel = selected?.OwnerLabel ?? "Unassigned";

            ReplaceCollection(_vm.SelectedEvidenceAndReasons,
                selected == null
                    ? Array.Empty<string>()
                    : selected.Evidence
                        .Concat(selected.RiskReasons)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .Take(8));

            ReplaceCollection(_vm.SelectedTags,
                selected == null
                    ? Array.Empty<string>()
                    : selected.ToModel().Tags.DefaultIfEmpty("Behavior"));

            ReplaceCollection(_vm.SelectedRuleIds,
                selected == null
                    ? Array.Empty<string>()
                    : selected.ToModel().RelatedEvents.Select(evt => evt.RuleId)
                        .Concat(selected.ToModel().RelatedAnomalies.SelectMany(anomaly => anomaly.RelatedRuleIds))
                        .Where(rule => !string.IsNullOrWhiteSpace(rule))
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .Take(8)
                        .DefaultIfEmpty("No related rules"));

            var incidents = _vm.All.Select(item => item.ToModel()).ToArray();
            ReplaceCollection(_vm.AffectedHosts,
                IncidentQueueProjectionService.BuildAffectedHosts(selected?.ToModel(), incidents).Select(AffectedHostVm.From));

            var checklist = IncidentQueueProjectionService.BuildResponseChecklist(selected?.ToModel())
                .Select(ChecklistItemVm.From)
                .ToArray();
            ReplaceCollection(_vm.ResponseChecklist, checklist);
            _vm.ChecklistSummary = $"{IncidentQueueProjectionService.CountCompleted(checklist.Select(item => item.ToProjection()).ToArray())} / {checklist.Length} completed";

            InvestigationBody.Visibility = selected == null ? Visibility.Collapsed : Visibility.Visible;
            DetailsEmptyState.Visibility = selected == null ? Visibility.Visible : Visibility.Collapsed;
        }

        private void RestoreSelection(string incidentId)
        {
            if (string.IsNullOrWhiteSpace(incidentId))
                return;

            var index = _filtered.FindIndex(item => string.Equals(item.Id, incidentId, StringComparison.OrdinalIgnoreCase));
            if (index < 0)
                return;

            _vm.CurrentPage = (index / PageSize) + 1;
            RefreshPageChips();
            RefreshVisibleQueue(incidentId);
        }

        private void UpdateEmptyState()
        {
            QueueEmptyState.Visibility = _vm.VisibleQueue.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            QueueList.Visibility = _vm.VisibleQueue.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        }

        private void PreviousPage_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.CurrentPage <= 1)
                return;

            _vm.CurrentPage--;
            RefreshPageChips();
            RefreshVisibleQueue(_vm.Selected?.Id);
        }

        private void NextPage_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.CurrentPage >= _vm.TotalPages)
                return;

            _vm.CurrentPage++;
            RefreshPageChips();
            RefreshVisibleQueue(_vm.Selected?.Id);
        }

        private void PageNumber_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not FrameworkElement { DataContext: QueuePageChipVm page })
                return;

            _vm.CurrentPage = page.PageNumber;
            RefreshPageChips();
            RefreshVisibleQueue(_vm.Selected?.Id);
        }

        private void InvestigateHost_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null)
                return;

            if (Window.GetWindow(this) is MainWindow window)
            {
                window.OpenHostIntegrityWorkspace();
                Clipboard.SetText(_vm.Selected.SourceLabel);
            }
        }

        private void OpenIncidentWorkspace_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null)
                return;

            if (Window.GetWindow(this) is MainWindow window)
                window.OpenIncidentWorkspace(_vm.Selected.Id);
        }

        private void OpenRawDetections_Click(object sender, RoutedEventArgs e)
        {
            if (Window.GetWindow(this) is MainWindow window)
                window.OpenRawDetectionsWorkspace();
        }

        private void OpenRawTraffic_Click(object sender, RoutedEventArgs e)
        {
            if (Window.GetWindow(this) is MainWindow window)
                window.OpenRawTrafficWorkspace();
        }

        private void OpenAnomalies_Click(object sender, RoutedEventArgs e)
        {
            if (Window.GetWindow(this) is MainWindow window)
                window.OpenAnomaliesWorkspace();
        }

        private void CopyJson_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null)
                return;

            Clipboard.SetText(JsonSerializer.Serialize(_vm.Selected.ToExportObject(), new JsonSerializerOptions { WriteIndented = true }));
        }

        private void CopyMarkdown_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null)
                return;

            Clipboard.SetText(_vm.Selected.ToMarkdown());
        }

        private void QueueRowMore_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not FrameworkElement { DataContext: IncidentVm incident })
                return;

            QueueList.SelectedItem = incident;
            _vm.Selected = incident;
            RefreshSelectedDetails();
            OpenActionsMenu(sender as FrameworkElement);
        }

        private void MoreActions_Click(object sender, RoutedEventArgs e)
            => OpenActionsMenu(sender as FrameworkElement);

        private void OpenActionsMenu(FrameworkElement? target)
        {
            if (target == null || _vm.Selected == null)
                return;

            var menu = new ContextMenu();
            menu.Items.Add(BuildMenuItem("Open incident workspace", OpenIncidentWorkspace_Click));
            menu.Items.Add(BuildMenuItem("Query detections", OpenRawDetections_Click));
            menu.Items.Add(BuildMenuItem("Open raw traffic", OpenRawTraffic_Click));
            menu.Items.Add(BuildMenuItem("View anomalies", OpenAnomalies_Click));
            menu.Items.Add(new Separator());
            menu.Items.Add(BuildMenuItem("Copy incident JSON", CopyJson_Click));
            menu.Items.Add(BuildMenuItem("Copy markdown report", CopyMarkdown_Click));
            target.ContextMenu = menu;
            menu.IsOpen = true;
        }

        private MenuItem BuildMenuItem(string label, RoutedEventHandler handler)
        {
            var item = new MenuItem { Header = label };
            item.Click += handler;
            return item;
        }

        private Brush ResolveBrush(string resourceKey)
            => Application.Current.TryFindResource(resourceKey) as Brush ?? Brushes.DodgerBlue;

        private static string BuildFooterSeveritySummary(IEnumerable<IncidentVm> incidents)
        {
            var all = incidents.ToArray();
            var critical = all.Count(item => string.Equals(item.Severity, "Critical", StringComparison.OrdinalIgnoreCase));
            var high = all.Count(item => string.Equals(item.Severity, "High", StringComparison.OrdinalIgnoreCase));
            var medium = all.Count(item => string.Equals(item.Severity, "Medium", StringComparison.OrdinalIgnoreCase));
            var low = all.Count(item => string.Equals(item.Severity, "Low", StringComparison.OrdinalIgnoreCase));
            return $"Severity: Critical {critical}  High {high}  Medium {medium}  Low {low}";
        }

        private static void ReplaceCollection<T>(ObservableCollection<T> target, IEnumerable<T> items)
        {
            target.Clear();
            foreach (var item in items)
                target.Add(item);
        }
    }

    public sealed class IncidentQueueVm : INotifyPropertyChanged
    {
        public ObservableCollection<IncidentVm> All { get; } = new();
        public ObservableCollection<IncidentVm> VisibleQueue { get; } = new();
        public ObservableCollection<QueueKpiVm> Kpis { get; } = new();
        public ObservableCollection<string> SelectedEvidenceAndReasons { get; } = new();
        public ObservableCollection<string> SelectedTags { get; } = new();
        public ObservableCollection<string> SelectedRuleIds { get; } = new();
        public ObservableCollection<AffectedHostVm> AffectedHosts { get; } = new();
        public ObservableCollection<ChecklistItemVm> ResponseChecklist { get; } = new();
        public ObservableCollection<QueuePageChipVm> PageNumbers { get; } = new();

        private IncidentVm? _selected;
        public IncidentVm? Selected
        {
            get => _selected;
            set
            {
                _selected = value;
                OnChanged();
            }
        }

        private string _queueCountLabel = "0 incidents";
        public string QueueCountLabel
        {
            get => _queueCountLabel;
            set { _queueCountLabel = value; OnChanged(); }
        }

        private string _filterSeverity = "All severities";
        public string FilterSeverity
        {
            get => _filterSeverity;
            set { _filterSeverity = value; OnChanged(); }
        }

        private string _filterStatus = "All statuses";
        public string FilterStatus
        {
            get => _filterStatus;
            set { _filterStatus = value; OnChanged(); }
        }

        private string _filterOwner = "All owners";
        public string FilterOwner
        {
            get => _filterOwner;
            set { _filterOwner = value; OnChanged(); }
        }

        private string _search = string.Empty;
        public string Search
        {
            get => _search;
            set { _search = value; OnChanged(); }
        }

        private string _selectedOwnerLabel = "Unassigned";
        public string SelectedOwnerLabel
        {
            get => _selectedOwnerLabel;
            set { _selectedOwnerLabel = value; OnChanged(); }
        }

        private string _checklistSummary = "0 / 0 completed";
        public string ChecklistSummary
        {
            get => _checklistSummary;
            set { _checklistSummary = value; OnChanged(); }
        }

        private string _footerSeveritySummary = string.Empty;
        public string FooterSeveritySummary
        {
            get => _footerSeveritySummary;
            set { _footerSeveritySummary = value; OnChanged(); }
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

        private string _pageSummary = "Showing 0-0 of 0 incidents";
        public string PageSummary
        {
            get => _pageSummary;
            set { _pageSummary = value; OnChanged(); }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public sealed record QueueKpiVm(string Title, string Value, string Delta, string Detail, Brush AccentBrush, string Glyph);

    public sealed class QueuePageChipVm : INotifyPropertyChanged
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

    public sealed class AffectedHostVm
    {
        public string Host { get; init; } = string.Empty;
        public string HostDisplay => FormatHostDisplay(Host);
        public string Role { get; init; } = string.Empty;
        public int RiskScore { get; init; }
        public string RiskScoreLabel => RiskScore.ToString();
        public int IncidentCount { get; init; }
        public string IncidentCountLabel => IncidentCount.ToString();
        public string TrendText { get; init; } = string.Empty;
        public string Severity { get; init; } = "Low";

        public static AffectedHostVm From(AffectedHostProjection projection)
            => new()
            {
                Host = projection.Host,
                Role = projection.Role,
                RiskScore = projection.RiskScore,
                IncidentCount = projection.IncidentCount,
                TrendText = projection.TrendText,
                Severity = projection.Severity
            };

        private static string FormatHostDisplay(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return "Unknown host";

            var host = value.Trim();
            if (host.Length <= 34)
                return host;

            if (host.Contains(':', StringComparison.Ordinal))
            {
                var parts = host.Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (parts.Length >= 4)
                    return $"{parts[0]}:{parts[1]}:...:{parts[^2]}:{parts[^1]}";
            }

            return $"{host[..18]}...{host[^10..]}";
        }
    }

    public sealed class ChecklistItemVm
    {
        public ChecklistItemVm()
        {
        }

        public ChecklistItemVm(string title, string status, bool isCompleted)
        {
            Title = title;
            Status = status;
            IsCompleted = isCompleted;
            StatusBrush = ResolveStatusBrush(status);
        }

        public int Index { get; init; }
        public string Title { get; init; } = string.Empty;
        public string Status { get; init; } = string.Empty;
        public bool IsCompleted { get; init; }
        public Brush StatusBrush { get; init; } = Brushes.SlateGray;

        public static ChecklistItemVm From(ResponseChecklistProjection projection)
        {
            return new ChecklistItemVm
            {
                Index = projection.Index,
                Title = projection.Title,
                Status = projection.Status,
                IsCompleted = string.Equals(projection.Status, "Done", StringComparison.OrdinalIgnoreCase),
                StatusBrush = ResolveStatusBrush(projection.Status)
            };
        }

        public ResponseChecklistProjection ToProjection()
            => new(Index, Title, Status);

        private static Brush ResolveStatusBrush(string? status)
        {
            var key = status switch
            {
                "Done" => "OkBrush",
                "In Progress" => "AccentBrush",
                _ => "TextMutedBrush"
            };

            return Application.Current?.TryFindResource(key) as Brush ?? Brushes.SlateGray;
        }
    }
}
