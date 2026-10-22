// SPDX-License-Identifier: MIT
// File: Views/IncidentsPage.xaml.cs
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Carthago.Analytics.Models;
using Carthago.Analytics.Services;
using Carthago.Sinks;

namespace Carthago.Views
{
    public partial class IncidentsPage : Page
    {
        private readonly SinkHost _host;
        private readonly Dispatcher _ui;
        private readonly IncidentsVm _vm;

        public IncidentsPage(SinkHost sinkHost, string workspaceTitle = "Incident Queue")
        {
            InitializeComponent();

            _host = sinkHost ?? throw new ArgumentNullException(nameof(sinkHost));
            _ui = Dispatcher;
            _vm = new IncidentsVm { WorkspaceTitle = workspaceTitle };
            DataContext = _vm;

            var analytics = _host.Analytics;
            analytics.IncidentCreated += OnIncidentChanged;
            analytics.IncidentUpdated += OnIncidentChanged;
            analytics.AnalysisProgress += OnProgress;
            analytics.SummaryReady += OnSummaryReady;
            analytics.StateReset += OnStateReset;

            Unloaded += (_, __) =>
            {
                analytics.IncidentCreated -= OnIncidentChanged;
                analytics.IncidentUpdated -= OnIncidentChanged;
                analytics.AnalysisProgress -= OnProgress;
                analytics.SummaryReady -= OnSummaryReady;
                analytics.StateReset -= OnStateReset;
            };

            SeverityFilter.SelectionChanged += (_, __) =>
            {
                _vm.FilterSeverity = (SeverityFilter.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "All";
                ApplyFilter();
            };

            IncidentsList.SelectionChanged += (_, __) =>
            {
                _vm.Selected = IncidentsList.SelectedItem as IncidentVm;
                UpdateSelectionState();
            };

            LoadInitialIncidents();
            ApplyFilter();
            UpdateSelectionState();
        }

        private void LoadInitialIncidents()
        {
            _vm.All.Clear();
            foreach (var incident in _host.Analytics.GetRecentIncidents(250))
                UpsertIncident(incident);

            SortView();

            if (_vm.All.Count > 0)
            {
                IncidentsList.SelectedIndex = 0;
                _vm.Selected = IncidentsList.SelectedItem as IncidentVm;
            }

            _vm.RefreshMetrics();
            UpdateEmptyStates();
        }

        private void OnStateReset()
            => _ui.BeginInvoke(new Action(() =>
            {
                LoadInitialIncidents();
                ApplyFilter();
                UpdateSelectionState();
            }));

        private void OnIncidentChanged(Incident incident)
            => _ui.BeginInvoke(new Action(() =>
            {
                UpsertIncident(incident);
                SortView();
                ApplyFilter();
                RestoreSelection(incident.Id);
                _vm.RefreshMetrics();
                UpdateEmptyStates();
            }));

        private void OnSummaryReady(string id, string text)
            => _ui.BeginInvoke(new Action(() =>
            {
                var item = _vm.All.FirstOrDefault(i => i.Id == id);
                if (item == null)
                    return;

                item.Summary = text;
                item.IsAnalyzing = false;
                item.ProgressText = "Completed";
            }));

        private void OnProgress(string id, string state)
            => _ui.BeginInvoke(new Action(() =>
            {
                var item = _vm.All.FirstOrDefault(i => i.Id == id);
                if (item == null)
                    return;

                switch (state?.ToLowerInvariant())
                {
                    case "queued":
                        item.IsAnalyzing = true;
                        item.ProgressText = "Queued";
                        break;
                    case "started":
                        item.IsAnalyzing = true;
                        item.ProgressText = "Preparing context";
                        break;
                    case "llm":
                        item.IsAnalyzing = true;
                        item.ProgressText = "Calling LLM";
                        break;
                    case "done":
                        item.IsAnalyzing = false;
                        item.ProgressText = "Completed";
                        break;
                    default:
                        if (!string.IsNullOrWhiteSpace(state) && state.StartsWith("failed", StringComparison.OrdinalIgnoreCase))
                        {
                            item.IsAnalyzing = false;
                            item.ProgressText = state;
                        }
                        break;
                }
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

        private void RestoreSelection(string incidentId)
        {
            if (string.IsNullOrWhiteSpace(incidentId))
                return;

            var match = _vm.All.FirstOrDefault(item => item.Id == incidentId);
            if (match == null)
                return;

            if (_vm.Selected?.Id == incidentId)
            {
                _vm.Selected = match;
                IncidentsList.SelectedItem = match;
                UpdateSelectionState();
            }
        }

        public void SelectIncident(string? incidentId)
        {
            if (string.IsNullOrWhiteSpace(incidentId))
                return;

            var match = _vm.All.FirstOrDefault(item => string.Equals(item.Id, incidentId, StringComparison.OrdinalIgnoreCase));
            if (match == null)
                return;

            _vm.Selected = match;
            IncidentsList.SelectedItem = match;
            IncidentsList.ScrollIntoView(match);
            UpdateSelectionState();
        }

        private void SortView()
        {
            var view = CollectionViewSource.GetDefaultView(_vm.All);
            if (view == null)
                return;

            using (view.DeferRefresh())
            {
                view.SortDescriptions.Clear();
                view.SortDescriptions.Add(new SortDescription(nameof(IncidentVm.IsResolved), ListSortDirection.Ascending));
                view.SortDescriptions.Add(new SortDescription(nameof(IncidentVm.RiskScore), ListSortDirection.Descending));
                view.SortDescriptions.Add(new SortDescription(nameof(IncidentVm.UpdatedUtc), ListSortDirection.Descending));
            }
        }

        private void ApplyFilter()
        {
            var view = CollectionViewSource.GetDefaultView(_vm.All);
            if (view == null)
                return;

            view.Filter = obj =>
            {
                if (obj is not IncidentVm item)
                    return false;

                if (!string.Equals(_vm.FilterSeverity, "All", StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(item.Severity, _vm.FilterSeverity, StringComparison.OrdinalIgnoreCase))
                    return false;

                if (_vm.OnlyUnacked && item.IsResolved)
                    return false;

                if (!string.IsNullOrWhiteSpace(_vm.Search))
                {
                    var q = _vm.Search.Trim();
                    var found = item.Title.Contains(q, StringComparison.OrdinalIgnoreCase)
                                || item.Summary.Contains(q, StringComparison.OrdinalIgnoreCase)
                                || item.SourceLabel.Contains(q, StringComparison.OrdinalIgnoreCase)
                                || item.DestinationLabel.Contains(q, StringComparison.OrdinalIgnoreCase)
                                || item.Evidence.Any(value => value.Contains(q, StringComparison.OrdinalIgnoreCase))
                                || item.RiskReasons.Any(value => value.Contains(q, StringComparison.OrdinalIgnoreCase));
                    if (!found)
                        return false;
                }

                return true;
            };

            view.Refresh();
            _vm.RefreshMetrics();
            UpdateEmptyStates();
        }

        private void UpdateSelectionState()
        {
            var hasSelection = _vm.Selected != null;
            DetailsScrollViewer.Visibility = hasSelection ? Visibility.Visible : Visibility.Collapsed;
            DetailsEmptyState.Visibility = hasSelection ? Visibility.Collapsed : Visibility.Visible;
        }

        private void UpdateEmptyStates()
        {
            var view = CollectionViewSource.GetDefaultView(_vm.All);
            var count = view?.Cast<object>().Count() ?? 0;
            IncidentsEmptyState.Visibility = count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            _vm.Search = SearchBox.Text ?? string.Empty;
            ApplyFilter();
        }

        private void OnlyUnackedBox_Changed(object sender, RoutedEventArgs e)
        {
            _vm.OnlyUnacked = OnlyUnackedBox.IsChecked == true;
            ApplyFilter();
        }

        private void CopySummary_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrWhiteSpace(_vm.Selected?.Summary))
                Clipboard.SetText(_vm.Selected.Summary);
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

        private void Clear_Click(object sender, RoutedEventArgs e)
        {
            _vm.All.Clear();
            _vm.Selected = null;
            UpdateSelectionState();
            UpdateEmptyStates();
        }

        private void Ack_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null)
                return;

            _host.Analytics.UpdateIncidentStatus(_vm.Selected.Id, "Acknowledged");
        }

        private void Resolve_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null)
                return;

            _host.Analytics.UpdateIncidentStatus(_vm.Selected.Id, "Resolved");
        }

        private void ConfirmSuspicious_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null)
                return;

            _host.Analytics.MarkIncidentConfirmedSuspicious(_vm.Selected.Id, NormalizeNote(_vm.Selected.AnalystNoteDraft));
        }

        private void MarkExpected_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null)
                return;

            _host.Analytics.MarkIncidentExpected(_vm.Selected.Id, NormalizeNote(_vm.Selected.AnalystNoteDraft));
        }

        private void MarkFalsePositive_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null)
                return;

            _host.Analytics.MarkIncidentFalsePositive(_vm.Selected.Id, NormalizeNote(_vm.Selected.AnalystNoteDraft));
        }

        private void SuppressSimilar_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null)
                return;

            var answer = MessageBox.Show(
                "Suppress similar incidents for this host/destination/category for 7 days? Threat-intel and critical evidence will still remain visible.",
                "Suppress Similar Incidents",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (answer != MessageBoxResult.Yes)
                return;

            _host.Analytics.SuppressSimilar(_vm.Selected.Id, TimeSpan.FromDays(7), NormalizeNote(_vm.Selected.AnalystNoteDraft));
        }

        private void TrustDestination_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null || !_vm.Selected.HasDestinationTrustCandidate)
                return;

            var answer = MessageBox.Show(
                $"Trust destination {_vm.Selected.DestinationLabel} for host {_vm.Selected.SourceLabel}? This reduces future destination-novelty risk for similar incidents.",
                "Trust Destination",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (answer != MessageBoxResult.Yes)
                return;

            _host.Analytics.TrustDestinationForHost(_vm.Selected.Id, NormalizeNote(_vm.Selected.AnalystNoteDraft));
        }

        private void TrustPort_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null || !_vm.Selected.HasPortTrustCandidate)
                return;

            var answer = MessageBox.Show(
                $"Trust destination port {_vm.Selected.PortLabel} for host {_vm.Selected.SourceLabel}? This reduces future port-novelty risk for similar incidents.",
                "Trust Port",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (answer != MessageBoxResult.Yes)
                return;

            _host.Analytics.TrustPortForHost(_vm.Selected.Id, NormalizeNote(_vm.Selected.AnalystNoteDraft));
        }

        private void TrustProcess_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null || !_vm.Selected.HasProcessTrustCandidate)
                return;

            var answer = MessageBox.Show(
                $"Trust process {_vm.Selected.ProcessLabel} for host {_vm.Selected.SourceLabel}? This reduces future process-related novelty risk for similar incidents.",
                "Trust Process",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (answer != MessageBoxResult.Yes)
                return;

            _host.Analytics.TrustProcessForHost(_vm.Selected.Id, NormalizeNote(_vm.Selected.AnalystNoteDraft));
        }

        private void SaveNote_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null)
                return;

            var note = NormalizeNote(_vm.Selected.AnalystNoteDraft);
            if (string.IsNullOrWhiteSpace(note))
                return;

            _host.Analytics.AddIncidentNote(_vm.Selected.Id, note);
        }

        private static string? NormalizeNote(string? note)
            => string.IsNullOrWhiteSpace(note) ? null : note.Trim();

        private void Page_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.F)
            {
                SearchBox.Focus();
                SearchBox.SelectAll();
                e.Handled = true;
            }
        }
    }

    public sealed class IncidentsVm : INotifyPropertyChanged
    {
        public ObservableCollection<IncidentVm> All { get; } = new();

        private string _workspaceTitle = "Incident Queue";
        public string WorkspaceTitle
        {
            get => _workspaceTitle;
            set
            {
                _workspaceTitle = string.IsNullOrWhiteSpace(value) ? "Incident Queue" : value;
                OnChanged();
                OnChanged(nameof(WorkspaceSubtitle));
            }
        }

        public string WorkspaceSubtitle => WorkspaceTitle.Contains("Queue", StringComparison.OrdinalIgnoreCase)
            ? "Operational triage queue with status, evidence, affected hosts, and response checklist."
            : "Correlated security incidents with evidence, timeline, and analyst guidance.";

        public int ActiveIncidentCount { get; private set; }
        public int CriticalIncidentCount { get; private set; }
        public int NewInHourCount { get; private set; }
        public int InInvestigationCount { get; private set; }
        public int ResolvedTodayCount { get; private set; }

        public void RefreshMetrics()
        {
            var now = DateTime.UtcNow;
            ActiveIncidentCount = All.Count(item => !item.IsResolved);
            CriticalIncidentCount = All.Count(item => string.Equals(item.Severity, "Critical", StringComparison.OrdinalIgnoreCase));
            NewInHourCount = All.Count(item => item.CreatedUtc >= now.AddHours(-1));
            InInvestigationCount = All.Count(item => item.Status.Contains("Investigat", StringComparison.OrdinalIgnoreCase)
                                                   || item.Status.Contains("Progress", StringComparison.OrdinalIgnoreCase)
                                                   || item.Status.Contains("Acknowledged", StringComparison.OrdinalIgnoreCase));
            ResolvedTodayCount = All.Count(item => item.IsResolved && item.UpdatedUtc.Date == now.Date);

            OnChanged(nameof(ActiveIncidentCount));
            OnChanged(nameof(CriticalIncidentCount));
            OnChanged(nameof(NewInHourCount));
            OnChanged(nameof(InInvestigationCount));
            OnChanged(nameof(ResolvedTodayCount));
        }

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

        private string _filterSeverity = "All";
        public string FilterSeverity
        {
            get => _filterSeverity;
            set
            {
                _filterSeverity = value;
                OnChanged();
            }
        }

        private string _search = "";
        public string Search
        {
            get => _search;
            set
            {
                _search = value;
                OnChanged();
            }
        }

        private bool _onlyUnacked;
        public bool OnlyUnacked
        {
            get => _onlyUnacked;
            set
            {
                _onlyUnacked = value;
                OnChanged();
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        public void OnChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public sealed class IncidentVm : INotifyPropertyChanged
    {
        private Incident? _model;

        public string Id { get; private set; } = "";
        public string Title { get; private set; } = "";
        public string Severity { get; private set; } = "Low";
        public string SeverityUpper => Severity.ToUpperInvariant();
        public int RiskScore { get; private set; }
        public string RiskScoreLabel => $"Risk {RiskScore}";
        public string RiskScoreNumber => RiskScore.ToString(CultureInfo.InvariantCulture);
        public string IncidentIdLabel => string.IsNullOrWhiteSpace(Id) ? "ID pending" : $"ID: {Id}";
        public bool IsDemo { get; private set; }
        public string DemoLabel => IsDemo ? "Simulated demo data" : string.Empty;
        public string Status { get; private set; } = "New";
        public string StatusUpper => Status.ToUpperInvariant();
        public string OwnerLabel => "Unassigned";
        public string Category { get; private set; } = "Behavior";
        public string SourceLabel { get; private set; } = "Unknown host";
        public string DestinationLabel { get; private set; } = "Unknown destination";
        public int RelatedAnomalyCount { get; private set; }
        public string RelatedAnomalyCountLabel => RelatedAnomalyCount.ToString(CultureInfo.InvariantCulture);
        public string OccurrenceLabel { get; private set; } = "1 related event";
        public string? AnalystFeedbackType { get; private set; }
        public string FeedbackStateLabel => string.IsNullOrWhiteSpace(AnalystFeedbackType) ? "No analyst feedback yet" : FormatFeedbackType(AnalystFeedbackType);
        public string? AnalystNote { get; private set; }
        public bool IsSuppressed { get; private set; }
        public DateTime? SuppressedUntilUtc { get; private set; }
        public string SuppressionLabel => SuppressedUntilUtc.HasValue
            ? $"Suppressed until {SuppressedUntilUtc.Value.ToLocalTime():yyyy-MM-dd HH:mm}"
            : "Not suppressed";
        public string? ProcessLabel { get; private set; }
        public string? PortLabel { get; private set; }
        public bool HasProcessTrustCandidate => !string.IsNullOrWhiteSpace(ProcessLabel);
        public bool HasPortTrustCandidate => !string.IsNullOrWhiteSpace(PortLabel);
        public bool HasDestinationTrustCandidate => !string.IsNullOrWhiteSpace(DestinationLabel) && !string.Equals(DestinationLabel, "Unknown destination", StringComparison.OrdinalIgnoreCase);
        public DateTime CreatedUtc { get; private set; }
        public DateTime UpdatedUtc { get; private set; }
        public string CreatedLabel => $"Created {CreatedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}";
        public string UpdatedLabel => $"Updated {UpdatedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}";
        public bool IsResolved => string.Equals(Status, "Resolved", StringComparison.OrdinalIgnoreCase);
        public ObservableCollection<string> TopEvidence { get; } = new();
        public ObservableCollection<string> Evidence { get; } = new();
        public ObservableCollection<string> RiskReasons { get; } = new();
        public ObservableCollection<string> FeedbackAppliedReasons { get; } = new();
        public ObservableCollection<string> RecommendedActions { get; } = new();
        public ObservableCollection<TimelineItemVm> TimelineItems { get; } = new();
        public ObservableCollection<string> RelatedAnomalyDescriptions { get; } = new();
        public ObservableCollection<string> RelatedEventDescriptions { get; } = new();
        public ObservableCollection<IncidentHostVm> AffectedHosts { get; } = new();
        public ObservableCollection<string> MitreTechniques { get; } = new();
        public ObservableCollection<string> Tags { get; } = new();
        public ObservableCollection<string> RuleIds { get; } = new();
        public ObservableCollection<ChecklistItemVm> ChecklistItems { get; } = new();

        private string _summary = "";
        public string Summary
        {
            get => _summary;
            set
            {
                _summary = value;
                OnChanged();
            }
        }

        private bool _isAnalyzing;
        public bool IsAnalyzing
        {
            get => _isAnalyzing;
            set
            {
                _isAnalyzing = value;
                OnChanged();
            }
        }

        private string _progressText = "";
        public string ProgressText
        {
            get => _progressText;
            set
            {
                _progressText = value;
                OnChanged();
            }
        }

        private string _analystNoteDraft = "";
        public string AnalystNoteDraft
        {
            get => _analystNoteDraft;
            set
            {
                _analystNoteDraft = value;
                OnChanged();
            }
        }

        public static IncidentVm From(Incident incident)
        {
            var vm = new IncidentVm();
            vm.UpdateFrom(incident);
            return vm;
        }

        public void UpdateFrom(Incident incident)
        {
            _model = CloneIncident(incident);
            Id = incident.Id;
            Title = string.IsNullOrWhiteSpace(incident.Title) ? "Incident" : incident.Title;
            Severity = string.IsNullOrWhiteSpace(incident.Severity) ? "Low" : incident.Severity;
            RiskScore = incident.RiskScore;
            IsDemo = incident.Tags.Any(tag => string.Equals(tag, "demo", StringComparison.OrdinalIgnoreCase)
                                           || tag.StartsWith("demo:", StringComparison.OrdinalIgnoreCase));
            Status = string.IsNullOrWhiteSpace(incident.Status) ? "New" : incident.Status;
            Category = string.IsNullOrWhiteSpace(incident.Category) ? "Behavior" : incident.Category;
            SourceLabel = string.IsNullOrWhiteSpace(incident.PrimarySourceIp) ? "Unknown host" : incident.PrimarySourceIp;
            DestinationLabel = incident.PrimaryDestinationHost ?? incident.PrimaryDestinationIp ?? "Unknown destination";
            RelatedAnomalyCount = incident.RelatedAnomalies.Count;
            OccurrenceLabel = incident.OccurrenceCount <= 1 ? $"{Math.Max(incident.RelatedEvents.Count, 1)} related event" : $"{incident.OccurrenceCount} correlated events";
            AnalystFeedbackType = incident.AnalystFeedbackType;
            AnalystNote = string.IsNullOrWhiteSpace(incident.AnalystNote) ? null : incident.AnalystNote;
            IsSuppressed = incident.IsSuppressed;
            SuppressedUntilUtc = incident.SuppressedUntilUtc;
            ProcessLabel = IncidentFeedbackStore.GetIncidentProcessName(incident);
            PortLabel = IncidentFeedbackStore.GetIncidentPort(incident);
            CreatedUtc = incident.CreatedUtc == default ? DateTime.UtcNow : incident.CreatedUtc;
            UpdatedUtc = incident.UpdatedUtc == default ? incident.LastSeenUtc == default ? incident.CreatedUtc : incident.LastSeenUtc : incident.UpdatedUtc;
            Summary = string.IsNullOrWhiteSpace(incident.Summary)
                ? incident.RiskReasons.FirstOrDefault()
                    ?? incident.Evidence.FirstOrDefault()
                    ?? "Summary pending. Review the supporting evidence below."
                : incident.Summary;

            ReplaceCollection(TopEvidence, incident.Evidence.Take(3).DefaultIfEmpty("Evidence is still being assembled."));
            ReplaceCollection(Evidence, incident.Evidence.DefaultIfEmpty("Evidence is still being assembled."));
            ReplaceCollection(RiskReasons, incident.RiskReasons.DefaultIfEmpty("Risk score is based on the current correlated evidence set."));
            ReplaceCollection(FeedbackAppliedReasons, incident.FeedbackAppliedReasons.DefaultIfEmpty("No feedback-based risk adjustments have been applied."));
            ReplaceCollection(RecommendedActions, incident.RecommendedActions.DefaultIfEmpty("Review the supporting telemetry and validate whether the behavior is expected."));
            ReplaceCollection(TimelineItems,
                incident.TimelineItems.Count == 0
                    ? new[] { TimelineItemVm.EmptyState("No incident story is available yet. Timeline items will appear here as detections, anomalies, risk changes, and analyst actions are recorded.") }
                    : incident.TimelineItems
                        .OrderBy(item => item.TimestampUtc)
                        .Select(TimelineItemVm.From)
                        .ToArray());
            ReplaceCollection(RelatedAnomalyDescriptions,
                incident.RelatedAnomalies.Count == 0
                    ? new[] { "No related anomalies are attached yet." }
                    : incident.RelatedAnomalies
                        .OrderByDescending(anomaly => anomaly.UpdatedUtc)
                        .Take(8)
                        .Select(anomaly => $"{anomaly.CreatedUtc:HH:mm:ss} • {anomaly.Title}"));
            ReplaceCollection(RelatedEventDescriptions,
                incident.RelatedEvents.Count == 0
                    ? new[] { "No related detections are attached yet." }
                    : incident.RelatedEvents
                        .OrderByDescending(evt => evt.Timestamp)
                        .Take(8)
                        .Select(evt => $"{evt.Timestamp:HH:mm:ss} • {evt.RuleId} • {evt.Description}"));

            ReplaceCollection(AffectedHosts, BuildAffectedHosts(incident));
            ReplaceCollection(MitreTechniques, BuildMitreTechniques(incident));
            ReplaceCollection(Tags, incident.Tags.Count == 0
                ? BuildDefaultTags(incident)
                : incident.Tags.Select(HumanizeToken).Distinct(StringComparer.OrdinalIgnoreCase));
            ReplaceCollection(RuleIds, incident.RelatedEvents
                .Select(evt => evt.RuleId)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .DefaultIfEmpty("No rule IDs"));
            ReplaceCollection(ChecklistItems, BuildChecklist(incident));

            IsAnalyzing = incident.IsAnalyzing;
            ProgressText = incident.IsAnalyzing ? "Analyzing" : ProgressText;
            AnalystNoteDraft = AnalystNote ?? string.Empty;

            OnChanged(nameof(Id));
            OnChanged(nameof(Title));
            OnChanged(nameof(Severity));
            OnChanged(nameof(SeverityUpper));
            OnChanged(nameof(RiskScore));
            OnChanged(nameof(RiskScoreLabel));
            OnChanged(nameof(RiskScoreNumber));
            OnChanged(nameof(IncidentIdLabel));
            OnChanged(nameof(IsDemo));
            OnChanged(nameof(DemoLabel));
            OnChanged(nameof(Status));
            OnChanged(nameof(StatusUpper));
            OnChanged(nameof(OwnerLabel));
            OnChanged(nameof(Category));
            OnChanged(nameof(SourceLabel));
            OnChanged(nameof(DestinationLabel));
            OnChanged(nameof(RelatedAnomalyCount));
            OnChanged(nameof(RelatedAnomalyCountLabel));
            OnChanged(nameof(OccurrenceLabel));
            OnChanged(nameof(AnalystFeedbackType));
            OnChanged(nameof(FeedbackStateLabel));
            OnChanged(nameof(AnalystNote));
            OnChanged(nameof(IsSuppressed));
            OnChanged(nameof(SuppressedUntilUtc));
            OnChanged(nameof(SuppressionLabel));
            OnChanged(nameof(ProcessLabel));
            OnChanged(nameof(PortLabel));
            OnChanged(nameof(HasProcessTrustCandidate));
            OnChanged(nameof(HasPortTrustCandidate));
            OnChanged(nameof(HasDestinationTrustCandidate));
            OnChanged(nameof(CreatedUtc));
            OnChanged(nameof(CreatedLabel));
            OnChanged(nameof(UpdatedUtc));
            OnChanged(nameof(UpdatedLabel));
            OnChanged(nameof(IsResolved));
        }

        public Incident ToModel()
        {
            if (_model != null)
                return CloneIncident(_model);

            return new Incident
            {
                Id = Id,
                Title = Title,
                Severity = Severity,
                RiskScore = RiskScore,
                CreatedUtc = CreatedUtc,
                UpdatedUtc = UpdatedUtc,
                LastSeenUtc = UpdatedUtc,
                PrimarySourceIp = string.Equals(SourceLabel, "Unknown host", StringComparison.OrdinalIgnoreCase) ? null : SourceLabel,
                PrimaryDestinationHost = string.Equals(DestinationLabel, "Unknown destination", StringComparison.OrdinalIgnoreCase) ? null : DestinationLabel,
                Category = Category,
                Status = Status,
                Summary = Summary,
                IsAnalyzing = IsAnalyzing,
                OccurrenceCount = Math.Max(RelatedEventDescriptions.Count, 1),
                Evidence = Evidence.ToList(),
                RecommendedActions = RecommendedActions.ToList(),
                Tags = Tags.ToList(),
                RiskReasons = RiskReasons.ToList(),
                FeedbackAppliedReasons = FeedbackAppliedReasons.ToList(),
                AnalystFeedbackType = AnalystFeedbackType,
                AnalystNote = AnalystNote,
                IsSuppressed = IsSuppressed,
                SuppressedUntilUtc = SuppressedUntilUtc
            };
        }

        private static IEnumerable<IncidentHostVm> BuildAffectedHosts(Incident incident)
        {
            var hosts = new Dictionary<string, IncidentHostVm>(StringComparer.OrdinalIgnoreCase);

            void add(string? host, string role, int risk, int count)
            {
                if (string.IsNullOrWhiteSpace(host))
                    return;
                if (hosts.TryGetValue(host, out var existing))
                {
                    existing.IncidentCount += Math.Max(1, count);
                    existing.RiskScore = Math.Max(existing.RiskScore, risk);
                    return;
                }

                hosts[host] = new IncidentHostVm
                {
                    Host = host,
                    Role = role,
                    RiskScore = Math.Clamp(risk, 0, 100),
                    IncidentCount = Math.Max(1, count)
                };
            }

            add(incident.PrimarySourceIp, "Source host", incident.RiskScore, incident.OccurrenceCount);
            add(incident.PrimaryDestinationHost ?? incident.PrimaryDestinationIp, "Destination", Math.Max(incident.RiskScore - 15, 0), 1);

            foreach (var evt in incident.RelatedEvents.Take(10))
            {
                add(evt.SourceIp, "Endpoint", incident.RiskScore, 1);
                add(evt.DestinationHost ?? evt.DestinationIp, "Remote endpoint", Math.Max(incident.RiskScore - 20, 0), 1);
            }

            return hosts.Values
                .OrderByDescending(host => host.RiskScore)
                .Take(6)
                .DefaultIfEmpty(new IncidentHostVm { Host = "No affected hosts recorded", Role = "Pending evidence", RiskScore = 0, IncidentCount = 0 });
        }

        private static IEnumerable<string> BuildMitreTechniques(Incident incident)
        {
            var text = string.Join(" ", incident.Title, incident.Category, string.Join(" ", incident.Tags), string.Join(" ", incident.RiskReasons), string.Join(" ", incident.Evidence)).ToLowerInvariant();

            if (text.Contains("lateral") || text.Contains("smb") || text.Contains("remote"))
                yield return "T1021 Remote Services";
            if (text.Contains("credential") || text.Contains("authentication") || text.Contains("login"))
                yield return "T1110 Brute Force";
            if (text.Contains("dns") || text.Contains("domain"))
                yield return "T1071.004 DNS";
            if (text.Contains("powershell") || text.Contains("process"))
                yield return "T1059 Command Interpreter";
            if (text.Contains("c2") || text.Contains("command") || text.Contains("control"))
                yield return "T1071 Application Layer Protocol";

            yield return "Technique mapping pending";
        }

        private static IEnumerable<string> BuildDefaultTags(Incident incident)
        {
            yield return HumanizeToken(incident.Category);
            yield return incident.Severity;
            if (!string.IsNullOrWhiteSpace(incident.PrimaryDestinationIp))
                yield return incident.PrimaryDestinationIp.Contains(':') ? "IPv6 activity" : "IPv4 activity";
            if (incident.IsSuppressed)
                yield return "Suppressed";
        }

        private static IEnumerable<ChecklistItemVm> BuildChecklist(Incident incident)
        {
            yield return new ChecklistItemVm("Validate incident context and scope", "Done", true);
            yield return new ChecklistItemVm("Review related detections and anomalies", incident.RelatedEvents.Count > 0 || incident.RelatedAnomalies.Count > 0 ? "Done" : "Pending", incident.RelatedEvents.Count > 0 || incident.RelatedAnomalies.Count > 0);
            yield return new ChecklistItemVm($"Investigate source host ({(string.IsNullOrWhiteSpace(incident.PrimarySourceIp) ? "unknown" : incident.PrimarySourceIp)})", incident.IsAnalyzing ? "In Progress" : "Pending", false);
            yield return new ChecklistItemVm("Collect host artifacts and logs", "Pending", false);
            yield return new ChecklistItemVm("Confirm containment actions if needed", "Pending", false);
            yield return new ChecklistItemVm("Document findings and resolution", string.Equals(incident.Status, "Resolved", StringComparison.OrdinalIgnoreCase) ? "Done" : "Pending", string.Equals(incident.Status, "Resolved", StringComparison.OrdinalIgnoreCase));
        }

        private static Incident CloneIncident(Incident incident)
        {
            return new Incident
            {
                Id = incident.Id,
                Title = incident.Title,
                Severity = incident.Severity,
                RiskScore = incident.RiskScore,
                FirstSeenUtc = incident.FirstSeenUtc,
                CreatedUtc = incident.CreatedUtc,
                UpdatedUtc = incident.UpdatedUtc,
                LastSeenUtc = incident.LastSeenUtc,
                PrimarySourceIp = incident.PrimarySourceIp,
                PrimaryDestinationIp = incident.PrimaryDestinationIp,
                PrimaryDestinationHost = incident.PrimaryDestinationHost,
                Category = incident.Category,
                Status = incident.Status,
                CorrelationKey = incident.CorrelationKey,
                Summary = incident.Summary,
                IsAnalyzing = incident.IsAnalyzing,
                OccurrenceCount = incident.OccurrenceCount,
                RelatedEvents = incident.RelatedEvents.ToList(),
                RelatedAnomalies = incident.RelatedAnomalies.ToList(),
                Evidence = incident.Evidence.ToList(),
                RecommendedActions = incident.RecommendedActions.ToList(),
                Tags = incident.Tags.ToList(),
                RiskReasons = incident.RiskReasons.ToList(),
                TimelineItems = incident.TimelineItems.ToList(),
                AnalystFeedbackType = incident.AnalystFeedbackType,
                AnalystNote = incident.AnalystNote,
                FeedbackAppliedReasons = incident.FeedbackAppliedReasons.ToList(),
                SuppressedUntilUtc = incident.SuppressedUntilUtc,
                IsSuppressed = incident.IsSuppressed,
                LastFeedbackUtc = incident.LastFeedbackUtc
            };
        }

        private static string HumanizeToken(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return "Unknown";

            var text = value.Replace("_", " ").Replace("-", " ").Trim();
            if (text.Length <= 2)
                return text.ToUpperInvariant();

            var builder = new System.Text.StringBuilder();
            for (var i = 0; i < text.Length; i++)
            {
                var c = text[i];
                if (i > 0 && char.IsUpper(c) && !char.IsWhiteSpace(text[i - 1]))
                    builder.Append(' ');
                builder.Append(c);
            }

            return CultureInfo.InvariantCulture.TextInfo.ToTitleCase(builder.ToString().ToLowerInvariant());
        }

        public object ToExportObject() => new
        {
            Id,
            Title,
            Severity,
            RiskScore,
            Category,
            Status,
            SourceLabel,
            DestinationLabel,
            Summary,
            AnalystFeedbackType,
            AnalystNote,
            IsSuppressed,
            SuppressedUntilUtc,
            CreatedUtc,
            UpdatedUtc,
            Evidence = Evidence.ToArray(),
            RiskReasons = RiskReasons.ToArray(),
            FeedbackAppliedReasons = FeedbackAppliedReasons.ToArray(),
            RecommendedActions = RecommendedActions.ToArray(),
            TimelineItems = TimelineItems.Select(item => item.ToExportObject()).ToArray(),
            RelatedAnomalies = RelatedAnomalyDescriptions.ToArray(),
            RelatedEvents = RelatedEventDescriptions.ToArray(),
            DemoLabel = DemoLabel
        };

        public string ToMarkdown()
        {
            static string JoinLines(IEnumerable<string> values)
                => string.Join(Environment.NewLine, values.Select(value => $"- {value}"));

            return string.Join(Environment.NewLine, new[]
            {
                $"# {Title}",
                string.Empty,
                $"- Severity: {Severity}",
                $"- Risk score: {RiskScore}",
                $"- Category: {Category}",
                $"- Status: {Status}",
                $"- Demo label: {(IsDemo ? DemoLabel : "None")}",
                $"- Analyst feedback: {FeedbackStateLabel}",
                $"- Suppression: {SuppressionLabel}",
                $"- Affected host: {SourceLabel}",
                $"- Destination: {DestinationLabel}",
                $"- Process: {ProcessLabel ?? "Unknown"}",
                $"- Destination port: {PortLabel ?? "Unknown"}",
                $"- Created: {CreatedUtc:u}",
                $"- Updated: {UpdatedUtc:u}",
                string.Empty,
                "## Summary",
                Summary,
                string.Empty,
                "## Analyst Note",
                string.IsNullOrWhiteSpace(AnalystNote) ? "No analyst note saved." : AnalystNote,
                string.Empty,
                "## Risk Reasons",
                JoinLines(RiskReasons),
                string.Empty,
                "## Feedback Adjustments",
                JoinLines(FeedbackAppliedReasons),
                string.Empty,
                "## Evidence",
                JoinLines(Evidence),
                string.Empty,
                "## Recommended Actions",
                JoinLines(RecommendedActions),
                string.Empty,
                "## Timeline",
                TimelineItemVm.ToMarkdown(TimelineItems),
                string.Empty,
                "## Related Anomalies",
                JoinLines(RelatedAnomalyDescriptions),
                string.Empty,
                "## Related Detections",
                JoinLines(RelatedEventDescriptions)
            });
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        public void OnChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

        private static void ReplaceCollection(ObservableCollection<string> target, IEnumerable<string> values)
        {
            target.Clear();
            foreach (var value in values)
                target.Add(value);
        }

        private static void ReplaceCollection<T>(ObservableCollection<T> target, IEnumerable<T> values)
        {
            target.Clear();
            foreach (var value in values)
                target.Add(value);
        }

        private static string FormatFeedbackType(string? feedbackType)
        {
            return feedbackType switch
            {
                "ConfirmedSuspicious" => "Confirmed suspicious",
                "ExpectedBehavior" => "Marked expected behavior",
                "FalsePositive" => "Marked false positive",
                "SuppressSimilar" => "Similar incidents suppressed",
                "TrustDestinationForHost" => "Destination trusted for host",
                "TrustPortForHost" => "Port trusted for host",
                "TrustProcessForHost" => "Process trusted for host",
                "AddNote" => "Analyst note saved",
                _ => "No analyst feedback yet"
            };
        }
    }


    public sealed class IncidentHostVm : INotifyPropertyChanged
    {
        private string _host = "";
        private string _role = "";
        private int _riskScore;
        private int _incidentCount;

        public string Host
        {
            get => _host;
            set
            {
                _host = value ?? "";
                OnChanged();
                OnChanged(nameof(HostDisplay));
            }
        }

        public string HostDisplay => FormatHostDisplay(Host);

        public string Role
        {
            get => _role;
            set
            {
                _role = value ?? "";
                OnChanged();
            }
        }

        public int RiskScore
        {
            get => _riskScore;
            set
            {
                _riskScore = Math.Clamp(value, 0, 100);
                OnChanged();
                OnChanged(nameof(RiskScoreLabel));
            }
        }

        public string RiskScoreLabel => RiskScore.ToString(CultureInfo.InvariantCulture);

        public int IncidentCount
        {
            get => _incidentCount;
            set
            {
                _incidentCount = Math.Max(0, value);
                OnChanged();
                OnChanged(nameof(IncidentCountLabel));
            }
        }

        public string IncidentCountLabel => IncidentCount.ToString(CultureInfo.InvariantCulture);

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

        private static string FormatHostDisplay(string? host)
        {
            if (string.IsNullOrWhiteSpace(host))
                return "Unknown host";

            var value = host.Trim();
            if (value.Length <= 32)
                return value;

            if (value.Contains(':'))
            {
                var parts = value.Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (parts.Length >= 4)
                    return $"{parts[0]}:{parts[1]}:…:{parts[^2]}:{parts[^1]}";
            }

            return $"{value[..16]}…{value[^10..]}";
        }
    }

    public sealed class TimelineItemVm
    {
        public string TimeLabel { get; init; } = "";
        public string TypeLabel { get; init; } = "";
        public string Title { get; init; } = "";
        public string Description { get; init; } = "";
        public string Severity { get; init; } = "info";
        public string RiskAfterLabel { get; init; } = "";
        public string EndpointLabel { get; init; } = "";
        public bool IsEmptyState { get; init; }

        public static TimelineItemVm From(IncidentTimelineItem item)
        {
            var endpoint = item.DestinationHost ?? item.DestinationIp;
            var endpointLabel = string.IsNullOrWhiteSpace(endpoint)
                ? (string.IsNullOrWhiteSpace(item.SourceIp) ? string.Empty : item.SourceIp!)
                : string.IsNullOrWhiteSpace(item.SourceIp)
                    ? endpoint!
                    : $"{item.SourceIp} -> {endpoint}";

            return new TimelineItemVm
            {
                TimeLabel = item.TimestampUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
                TypeLabel = FormatType(item.Type),
                Title = item.Title,
                Description = item.Description,
                Severity = string.IsNullOrWhiteSpace(item.Severity) ? "info" : item.Severity,
                RiskAfterLabel = item.RiskScoreAfter.HasValue ? $"Risk after event: {item.RiskScoreAfter.Value}" : string.Empty,
                EndpointLabel = endpointLabel,
                IsEmptyState = false
            };
        }

        public static TimelineItemVm EmptyState(string message)
        {
            return new TimelineItemVm
            {
                TimeLabel = string.Empty,
                TypeLabel = "Story",
                Title = "Timeline is still building",
                Description = message,
                Severity = "info",
                RiskAfterLabel = string.Empty,
                EndpointLabel = string.Empty,
                IsEmptyState = true
            };
        }

        private static IEnumerable<IncidentHostVm> BuildAffectedHosts(Incident incident)
        {
            var hosts = new Dictionary<string, IncidentHostVm>(StringComparer.OrdinalIgnoreCase);

            void add(string? host, string role, int risk, int count)
            {
                if (string.IsNullOrWhiteSpace(host))
                    return;
                if (hosts.TryGetValue(host, out var existing))
                {
                    existing.IncidentCount += Math.Max(1, count);
                    existing.RiskScore = Math.Max(existing.RiskScore, risk);
                    return;
                }

                hosts[host] = new IncidentHostVm
                {
                    Host = host,
                    Role = role,
                    RiskScore = Math.Clamp(risk, 0, 100),
                    IncidentCount = Math.Max(1, count)
                };
            }

            add(incident.PrimarySourceIp, "Source host", incident.RiskScore, incident.OccurrenceCount);
            add(incident.PrimaryDestinationHost ?? incident.PrimaryDestinationIp, "Destination", Math.Max(incident.RiskScore - 15, 0), 1);

            foreach (var evt in incident.RelatedEvents.Take(10))
            {
                add(evt.SourceIp, "Endpoint", incident.RiskScore, 1);
                add(evt.DestinationHost ?? evt.DestinationIp, "Remote endpoint", Math.Max(incident.RiskScore - 20, 0), 1);
            }

            return hosts.Values
                .OrderByDescending(host => host.RiskScore)
                .Take(6)
                .DefaultIfEmpty(new IncidentHostVm { Host = "No affected hosts recorded", Role = "Pending evidence", RiskScore = 0, IncidentCount = 0 });
        }

        private static IEnumerable<string> BuildMitreTechniques(Incident incident)
        {
            var text = string.Join(" ", incident.Title, incident.Category, string.Join(" ", incident.Tags), string.Join(" ", incident.RiskReasons), string.Join(" ", incident.Evidence)).ToLowerInvariant();

            if (text.Contains("lateral") || text.Contains("smb") || text.Contains("remote"))
                yield return "T1021 Remote Services";
            if (text.Contains("credential") || text.Contains("authentication") || text.Contains("login"))
                yield return "T1110 Brute Force";
            if (text.Contains("dns") || text.Contains("domain"))
                yield return "T1071.004 DNS";
            if (text.Contains("powershell") || text.Contains("process"))
                yield return "T1059 Command Interpreter";
            if (text.Contains("c2") || text.Contains("command") || text.Contains("control"))
                yield return "T1071 Application Layer Protocol";

            yield return "Technique mapping pending";
        }

        private static IEnumerable<string> BuildDefaultTags(Incident incident)
        {
            yield return HumanizeToken(incident.Category);
            yield return incident.Severity;
            if (!string.IsNullOrWhiteSpace(incident.PrimaryDestinationIp))
                yield return incident.PrimaryDestinationIp.Contains(':') ? "IPv6 activity" : "IPv4 activity";
            if (incident.IsSuppressed)
                yield return "Suppressed";
        }

        private static IEnumerable<ChecklistItemVm> BuildChecklist(Incident incident)
        {
            yield return new ChecklistItemVm("Validate incident context and scope", "Done", true);
            yield return new ChecklistItemVm("Review related detections and anomalies", incident.RelatedEvents.Count > 0 || incident.RelatedAnomalies.Count > 0 ? "Done" : "Pending", incident.RelatedEvents.Count > 0 || incident.RelatedAnomalies.Count > 0);
            yield return new ChecklistItemVm($"Investigate source host ({(string.IsNullOrWhiteSpace(incident.PrimarySourceIp) ? "unknown" : incident.PrimarySourceIp)})", incident.IsAnalyzing ? "In Progress" : "Pending", false);
            yield return new ChecklistItemVm("Collect host artifacts and logs", "Pending", false);
            yield return new ChecklistItemVm("Confirm containment actions if needed", "Pending", false);
            yield return new ChecklistItemVm("Document findings and resolution", string.Equals(incident.Status, "Resolved", StringComparison.OrdinalIgnoreCase) ? "Done" : "Pending", string.Equals(incident.Status, "Resolved", StringComparison.OrdinalIgnoreCase));
        }

        private static string HumanizeToken(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return "Unknown";

            var text = value.Replace("_", " ").Replace("-", " ").Trim();
            if (text.Length <= 2)
                return text.ToUpperInvariant();

            var builder = new System.Text.StringBuilder();
            for (var i = 0; i < text.Length; i++)
            {
                var c = text[i];
                if (i > 0 && char.IsUpper(c) && !char.IsWhiteSpace(text[i - 1]))
                    builder.Append(' ');
                builder.Append(c);
            }

            return CultureInfo.InvariantCulture.TextInfo.ToTitleCase(builder.ToString().ToLowerInvariant());
        }

        public object ToExportObject() => new
        {
            TimeLabel,
            TypeLabel,
            Title,
            Description,
            Severity,
            RiskAfterLabel,
            EndpointLabel,
            IsEmptyState
        };

        public static string ToMarkdown(IEnumerable<TimelineItemVm> items)
        {
            var lines = items.Select(item =>
            {
                var risk = string.IsNullOrWhiteSpace(item.RiskAfterLabel) ? string.Empty : $" ({item.RiskAfterLabel})";
                var endpoint = string.IsNullOrWhiteSpace(item.EndpointLabel) ? string.Empty : $" [{item.EndpointLabel}]";
                return $"- {item.TimeLabel} [{item.TypeLabel}] {item.Title}{risk}{endpoint}: {item.Description}";
            });

            return string.Join(Environment.NewLine, lines);
        }

        private static string FormatType(string? type)
        {
            return type switch
            {
                "MlSignal" => "ML-assisted",
                "RiskChange" => "Risk change",
                "RecommendedAction" => "Recommended action",
                "StatusChange" => "Status change",
                "DemoStep" => "Demo step",
                "TrustRule" => "Trust rule",
                _ => string.IsNullOrWhiteSpace(type) ? "Story" : type
            };
        }
    }

    public sealed class SeverityToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            var severity = value?.ToString()?.ToLowerInvariant();
            var key = severity switch
            {
                "critical" => "SeverityCriticalBrush",
                "high" => "SeverityHighBrush",
                "medium" => "SeverityMediumBrush",
                "low" => "SeverityLowBrush",
                _ => "SeverityUnknownBrush"
            };

            return Application.Current.TryFindResource(key) as Brush
                ?? Brushes.SlateGray;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => Binding.DoNothing;
    }
}
