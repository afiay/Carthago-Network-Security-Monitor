// SPDX-License-Identifier: MIT
// File: Views/AnomaliesPage.xaml.cs
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
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Carthago.Analytics.Models;
using Carthago.Sinks;

namespace Carthago.Views
{
    public partial class AnomaliesPage : Page, IResponsiveLayoutAware
    {
        private readonly SinkHost _host;
        private readonly Dispatcher _ui;
        private readonly AnomaliesVm _vm;
        private readonly Dictionary<string, IncidentLink> _incidentLinks = new(StringComparer.OrdinalIgnoreCase);
        private readonly Action? _openRawTraffic;
        private readonly Action? _openRawDetections;
        private readonly Action? _openIncidentQueue;
        private readonly Action<string?>? _openIncidentWorkspace;
        private readonly Action? _openHostIntegrity;
        private readonly Action? _openAnalytics;
        private readonly Action? _openDetectionRules;
        private List<AnomalyVm> _filtered = new();
        private bool _suppressFilterRefresh;

        public void ApplyResponsiveLayout(ResponsiveLayoutMode mode)
        {
            KpiGrid.Columns = mode switch
            {
                ResponsiveLayoutMode.Compact => 2,
                ResponsiveLayoutMode.Standard => 3,
                _ => 5
            };

            ResponsiveLayout.ApplyAdaptiveColumns(
                mode,
                new[] { PrimaryWorkspaceQueueColumn, PrimaryWorkspaceDetailColumn },
                new[] { PrimaryWorkspaceTopRow, PrimaryWorkspaceBottomRow },
                new FrameworkElement[] { QueuePanel, InvestigationPanel },
                new[] { 0.45, 0.55 },
                12);

            ResponsiveLayout.ApplyAdaptiveColumns(
                mode,
                new[] { SupportingWorkspaceFirstColumn, SupportingWorkspaceSecondColumn, SupportingWorkspaceThirdColumn },
                new[] { SupportingWorkspaceFirstRow, SupportingWorkspaceSecondRow, SupportingWorkspaceThirdRow },
                new FrameworkElement[] { EntityHistoryPanel, BaselineDriftPanel, ModelSummaryPanel },
                new[] { 0.35, 0.37, 0.28 },
                12);
        }

        public AnomaliesPage(SinkHost sinkHost)
            : this(sinkHost, null, null, null, null, null, null, null)
        {
        }

        public AnomaliesPage(
            SinkHost sinkHost,
            Action? openRawTraffic,
            Action? openRawDetections,
            Action? openIncidentQueue,
            Action<string?>? openIncidentWorkspace,
            Action? openHostIntegrity,
            Action? openAnalytics,
            Action? openDetectionRules)
        {
            InitializeComponent();
            ResponsiveLayout.ApplyWhenLoaded(this, ApplyResponsiveLayout);

            _host = sinkHost ?? throw new ArgumentNullException(nameof(sinkHost));
            _openRawTraffic = openRawTraffic;
            _openRawDetections = openRawDetections;
            _openIncidentQueue = openIncidentQueue;
            _openIncidentWorkspace = openIncidentWorkspace;
            _openHostIntegrity = openHostIntegrity;
            _openAnalytics = openAnalytics;
            _openDetectionRules = openDetectionRules;
            _ui = Dispatcher;
            _vm = new AnomaliesVm();
            DataContext = _vm;

            var analytics = _host.Analytics;
            analytics.AnomalyObserved += OnAnomalyObserved;
            analytics.IncidentCreated += OnIncidentChanged;
            analytics.IncidentUpdated += OnIncidentChanged;
            analytics.BaselineStatusChanged += OnBaselineChanged;
            analytics.StateReset += OnStateReset;

            Unloaded += (_, __) =>
            {
                analytics.AnomalyObserved -= OnAnomalyObserved;
                analytics.IncidentCreated -= OnIncidentChanged;
                analytics.IncidentUpdated -= OnIncidentChanged;
                analytics.BaselineStatusChanged -= OnBaselineChanged;
                analytics.StateReset -= OnStateReset;
            };

            CategoryFilter.SelectionChanged += (_, __) =>
            {
                if (_suppressFilterRefresh)
                    return;

                _vm.FilterCategory = CategoryFilter.SelectedItem?.ToString() ?? "All categories";
                _vm.CurrentPage = 1;
                ApplyFilter();
            };

            SeverityFilter.SelectionChanged += (_, __) =>
            {
                if (_suppressFilterRefresh)
                    return;

                _vm.FilterSeverity = (SeverityFilter.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "All severities";
                _vm.CurrentPage = 1;
                ApplyFilter();
            };

            AnomaliesList.SelectionChanged += (_, __) =>
            {
                _vm.Selected = AnomaliesList.SelectedItem as AnomalyVm;
                UpdateSelectionState();
            };

            LoadInitialData();
            ApplyFilter();
        }

        private void LoadInitialData()
        {
            _vm.All.Clear();
            _vm.Visible.Clear();
            _vm.Selected = null;
            _vm.RawSignalCount = 0;
            RebuildIncidentLinks();
            UpdateBaselineStatus(_host.Analytics.GetBaselineStatus());

            var recentAnomalies = _host.Analytics.GetRecentAnomalies(400).ToList();
            _vm.RawSignalCount = recentAnomalies.Count;

            foreach (var anomaly in recentAnomalies)
                UpsertAnomaly(anomaly);

            RefreshCategoryOptions();
            _vm.RefreshMetrics();
            UpdateQueueFooter();
        }

        private void OnStateReset()
            => _ui.BeginInvoke(new Action(() =>
            {
                LoadInitialData();
                ApplyFilter();
                UpdateSelectionState();
            }));

        private void OnAnomalyObserved(AnomalySignal anomaly)
            => _ui.BeginInvoke(new Action(() =>
            {
                _vm.RawSignalCount++;
                UpsertAnomaly(anomaly);
                RefreshCategoryOptions();
                ApplyFilter();
                SelectAnomaly(anomaly.Id);
            }));

        private void OnIncidentChanged(Incident incident)
            => _ui.BeginInvoke(new Action(() =>
            {
                RebuildIncidentLinks();
                RefreshIncidentLinks();
                ApplyFilter();
            }));

        private void OnBaselineChanged(BaselineStatus status)
            => _ui.BeginInvoke(new Action(() =>
            {
                UpdateBaselineStatus(status ?? new BaselineStatus());
                _vm.RefreshMetrics();
            }));

        private void RebuildIncidentLinks()
        {
            _incidentLinks.Clear();

            foreach (var incident in _host.Analytics.GetRecentIncidents(300))
            {
                foreach (var anomaly in incident.RelatedAnomalies)
                {
                    if (string.IsNullOrWhiteSpace(anomaly.Id))
                        continue;

                    _incidentLinks[anomaly.Id] = IncidentLink.From(incident);
                }
            }
        }

        private void RefreshIncidentLinks()
        {
            foreach (var anomaly in _vm.All)
            {
                _incidentLinks.TryGetValue(anomaly.Id, out var link);
                anomaly.ApplyIncidentLink(link);
            }
        }

        private void UpdateBaselineStatus(BaselineStatus status)
        {
            var confidence = string.IsNullOrWhiteSpace(status.Confidence) ? "Low" : CapitalizeValue(status.Confidence);
            _vm.BaselineConfidenceLabel = confidence;
            _vm.BaselineHeadline = $"Baseline learning - confidence: {confidence}";

            if (status.ObservedHosts <= 0)
            {
                _vm.BaselineDetail = "More observations are needed before strong anomaly scoring is available.";
                _vm.BaselineHealthText = "Learning in progress";
                return;
            }

            _vm.BaselineDetail =
                $"{status.ObservedHosts} hosts observed, {status.LearningWindowMinutes} minute learning window, last update {FormatTime(status.LastUpdatedUtc)}";
            _vm.BaselineHealthText =
                $"{status.HighConfidenceHosts} high-confidence hosts, {status.MediumConfidenceHosts} medium, {status.LowConfidenceHosts} low";
        }

        private void UpsertAnomaly(AnomalySignal anomaly)
        {
            _incidentLinks.TryGetValue(anomaly.Id, out var link);

            var existing = _vm.All.FirstOrDefault(item => item.Id == anomaly.Id);
            if (existing != null)
            {
                existing.UpdateFrom(anomaly, link);
                return;
            }

            var groupKey = AnomalyVm.BuildGroupKey(anomaly);
            var existingGroup = _vm.All.FirstOrDefault(item =>
                string.Equals(item.GroupKey, groupKey, StringComparison.OrdinalIgnoreCase));

            if (existingGroup != null)
            {
                existingGroup.MergeFrom(anomaly, link);
                return;
            }

            _vm.All.Add(AnomalyVm.From(anomaly, link));
        }

        private void ApplyFilter()
        {
            RefreshCategoryOptions();

            _filtered = _vm.All
                .Where(MatchesFilter)
                .OrderByDescending(item => item.ScoreValue)
                .ThenByDescending(item => SeverityRank(item.Severity))
                .ThenByDescending(item => item.HasRelatedIncident)
                .ThenByDescending(item => item.LastSeenUtc)
                .ToList();

            if (_vm.Selected != null)
            {
                var selectedIndex = _filtered.FindIndex(item => string.Equals(item.Id, _vm.Selected.Id, StringComparison.OrdinalIgnoreCase));
                if (selectedIndex >= 0)
                    _vm.CurrentPage = (selectedIndex / _vm.PageSize) + 1;
                else
                    _vm.CurrentPage = 1;
            }
            else
            {
                _vm.CurrentPage = 1;
            }

            RebuildVisiblePage(true);
            _vm.RefreshMetrics();
            UpdateQueueFooter();
        }

        private bool MatchesFilter(AnomalyVm item)
        {
            if (!string.Equals(_vm.FilterCategory, "All categories", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(item.CategoryLabel, _vm.FilterCategory, StringComparison.OrdinalIgnoreCase))
                return false;

            if (!string.Equals(_vm.FilterSeverity, "All severities", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(item.Severity, _vm.FilterSeverity, StringComparison.OrdinalIgnoreCase))
                return false;

            if (_vm.OnlyLinked && !item.HasRelatedIncident)
                return false;

            if (!string.IsNullOrWhiteSpace(_vm.Search))
            {
                var q = _vm.Search.Trim();
                var found = item.Title.Contains(q, StringComparison.OrdinalIgnoreCase)
                            || item.DisplayTitle.Contains(q, StringComparison.OrdinalIgnoreCase)
                            || item.Description.Contains(q, StringComparison.OrdinalIgnoreCase)
                            || item.SourceLabel.Contains(q, StringComparison.OrdinalIgnoreCase)
                            || item.DestinationLabel.Contains(q, StringComparison.OrdinalIgnoreCase)
                            || item.Category.Contains(q, StringComparison.OrdinalIgnoreCase)
                            || item.CategoryLabel.Contains(q, StringComparison.OrdinalIgnoreCase)
                            || item.Reasons.Any(value => value.Contains(q, StringComparison.OrdinalIgnoreCase))
                            || item.EvidenceHighlights.Any(value => value.Contains(q, StringComparison.OrdinalIgnoreCase))
                            || item.RelatedIncidentHeadline.Contains(q, StringComparison.OrdinalIgnoreCase)
                            || item.Guidance.Any(value => value.Contains(q, StringComparison.OrdinalIgnoreCase))
                            || item.RelatedRuleIds.Any(value => value.Contains(q, StringComparison.OrdinalIgnoreCase));
                if (!found)
                    return false;
            }

            return true;
        }

        private void RebuildVisiblePage(bool preserveSelection)
        {
            var total = _filtered.Count;
            _vm.FilteredCount = total;
            _vm.TotalPages = Math.Max(1, (int)Math.Ceiling(total / (double)_vm.PageSize));
            _vm.CurrentPage = Math.Clamp(_vm.CurrentPage, 1, _vm.TotalPages);
            _vm.CanPageBack = _vm.CurrentPage > 1;
            _vm.CanPageForward = _vm.CurrentPage < _vm.TotalPages;

            var skip = (_vm.CurrentPage - 1) * _vm.PageSize;
            var pageItems = _filtered.Skip(skip).Take(_vm.PageSize).ToList();

            ReplaceCollection(_vm.Visible, pageItems);
            RefreshPageChips();

            AnomalyVm? nextSelection = null;
            if (preserveSelection && _vm.Selected != null)
                nextSelection = pageItems.FirstOrDefault(item => string.Equals(item.Id, _vm.Selected.Id, StringComparison.OrdinalIgnoreCase));

            nextSelection ??= pageItems.FirstOrDefault();

            _vm.Selected = nextSelection;
            AnomaliesList.SelectedItem = nextSelection;
            UpdateEmptyStates();
            UpdateSelectionState();
        }

        private void RefreshPageChips()
        {
            _vm.PageChips.Clear();

            var start = Math.Max(1, _vm.CurrentPage - 2);
            var end = Math.Min(_vm.TotalPages, start + 4);
            start = Math.Max(1, end - 4);

            for (var page = start; page <= end; page++)
            {
                _vm.PageChips.Add(new PageChipVm(page, page.ToString(CultureInfo.InvariantCulture), page == _vm.CurrentPage));
            }
        }

        private void RefreshCategoryOptions()
        {
            _suppressFilterRefresh = true;

            var selected = string.IsNullOrWhiteSpace(_vm.FilterCategory) ? "All categories" : _vm.FilterCategory;
            var categories = _vm.All
                .Select(item => item.CategoryLabel)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
                .ToList();

            _vm.CategoryOptions.Clear();
            _vm.CategoryOptions.Add("All categories");
            foreach (var category in categories)
                _vm.CategoryOptions.Add(category);

            if (!_vm.CategoryOptions.Contains(selected))
                _vm.FilterCategory = "All categories";

            CategoryFilter.SelectedItem = _vm.FilterCategory;
            _suppressFilterRefresh = false;
        }

        private void SelectAnomaly(string anomalyId)
        {
            if (string.IsNullOrWhiteSpace(anomalyId))
                return;

            var index = _filtered.FindIndex(item => string.Equals(item.Id, anomalyId, StringComparison.OrdinalIgnoreCase));
            if (index < 0)
                return;

            _vm.CurrentPage = (index / _vm.PageSize) + 1;
            RebuildVisiblePage(true);
        }

        private void UpdateSelectionState()
        {
            var selected = _vm.Selected;
            var hasSelection = selected != null;

            InvestigationBody.Visibility = hasSelection ? Visibility.Visible : Visibility.Collapsed;
            DetailsEmptyState.Visibility = hasSelection ? Visibility.Collapsed : Visibility.Visible;

            _vm.CanPivotToHost = hasSelection && (!string.IsNullOrWhiteSpace(selected?.SourceLabel) || _openHostIntegrity != null || _openAnalytics != null);
            _vm.CanCopyEvidence = hasSelection;
            _vm.CanOpenRawTraffic = hasSelection && _openRawTraffic != null;
            _vm.CanOpenRawDetections = hasSelection && _openRawDetections != null;
            _vm.CanOpenIncidentQueue = _openIncidentQueue != null;
            _vm.CanOpenDetectionRules = hasSelection && _openDetectionRules != null;
            _vm.CanAddToWatchlist = hasSelection;
            _vm.CanMarkExpected = hasSelection && selected!.HasRelatedIncident;
            _vm.CanOpenIncident = hasSelection;
            _vm.IncidentActionLabel = selected?.HasRelatedIncident == true ? "View Related Incident" : "Escalate to Incident";

            if (!hasSelection)
            {
                _vm.ModelSummary = "Select an anomaly to see baseline drift, feature evidence, and next actions.";
                _vm.BaselineNormalLabel = "No selection";
                _vm.BaselineCurrentLabel = "No selection";
                _vm.BaselineDeviationLabel = "0%";
                _vm.BaselineStatusText = "No anomaly selected yet.";
                _vm.PeerGroupLabel = "No peer group";
                _vm.SelectedWindowLabel = "Select an anomaly to inspect host and model context.";
                _vm.PeerGroupHeader = "Inferred peer group unavailable";
                ReplaceCollection(_vm.ModelExplanationPoints, Array.Empty<string>());
                ReplaceCollection(_vm.TopMlSignals, Array.Empty<AnomalySignalBarVm>());
                ReplaceCollection(_vm.EntityHistoryRows, Array.Empty<AnomalyMetricRowVm>());
                ReplaceCollection(_vm.BaselineDriftRows, Array.Empty<AnomalyMetricRowVm>());
                return;
            }

            PopulateInvestigation(selected!);
        }

        private void PopulateInvestigation(AnomalyVm selected)
        {
            var sameHost = _vm.All
                .Where(item => string.Equals(item.SourceLabel, selected.SourceLabel, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(item => item.LastSeenUtc)
                .ToList();

            var sameCategory = _vm.All
                .Where(item => string.Equals(item.Category, selected.Category, StringComparison.OrdinalIgnoreCase))
                .ToList();

            var hostLabel = BuildWindowLabel(sameHost);
            _vm.SelectedWindowLabel = $"{selected.SourceLabel} ({hostLabel})";

            var peerGroups = sameCategory
                .GroupBy(item => item.SourceLabel)
                .Where(group => !string.IsNullOrWhiteSpace(group.Key))
                .ToList();

            var inferredPeerGroup = InferPeerGroup(selected);
            var metricSelector = SelectPrimaryComparisonMetric(selected);
            var metricLabel = ResolvePrimaryMetricLabel(selected);
            var peerAverage = peerGroups.Count == 0 ? 0d : peerGroups.Average(group => metricSelector(group));
            var hostCount = metricSelector(sameHost);
            var hostDeviation = PercentDifference(hostCount, peerAverage);

            _vm.BaselineNormalLabel = peerAverage <= 0d
                ? "Baseline still learning"
                : $"{FormatMetricNumber(peerAverage)} {metricLabel}";
            _vm.BaselineCurrentLabel = $"{FormatMetricNumber(hostCount)} {metricLabel}";
            _vm.BaselineDeviationLabel = FormatSignedPercent(hostDeviation);
            _vm.BaselineStatusText = peerAverage <= 0d
                ? "Baseline still learning. Not enough historical traffic to compare this host against normal behavior."
                : "Current behavior is compared against recent peer-normal patterns for the same anomaly family.";
            _vm.PeerGroupLabel = BuildPeerRankLabel(selected, sameCategory);
            _vm.PeerGroupHeader = $"Inferred peer group: {inferredPeerGroup}";

            var modelSignals = BuildTopMlSignals(selected);
            ReplaceCollection(_vm.TopMlSignals, modelSignals);
            ReplaceCollection(_vm.ModelExplanationPoints, BuildModelExplanation(selected));
            ReplaceCollection(_vm.EntityHistoryRows, BuildEntityHistoryRows(selected, sameHost));
            ReplaceCollection(_vm.BaselineDriftRows, BuildBaselineDriftRows(selected, sameCategory));

            _vm.ModelSummary = BuildModelSummary(selected);
        }

        private IEnumerable<string> BuildModelExplanation(AnomalyVm selected)
        {
            var points = new List<string>();

            foreach (var reason in selected.Reasons.Take(3))
                points.Add(reason);

            if (selected.RelatedRuleIds.Count > 0)
                points.Add($"{selected.RelatedRuleIds.First()} matched within the current investigation window.");

            if (HasMlFeature(selected, "OutboundBytes"))
                points.Add("Outbound volume diverged from the learned baseline for this host window.");

            if (HasMlFeature(selected, "UniqueDestinationCount") || HasMlFeature(selected, "NewDestinationCount"))
                points.Add("Destination novelty or fan-out exceeded the host's recent behavior pattern.");

            if (HasMlFeature(selected, "RuleHitCount") || HasMlFeature(selected, "SeverityWeightedRuleCount"))
                points.Add("Rule intensity increased sharply inside the same anomaly window.");

            if (HasMlFeature(selected, "ThreatIntelHitCount"))
                points.Add("Threat-intelligence matches concentrated in the same behavior window.");

            if (selected.HasRelatedIncident)
                points.Add(selected.RelatedIncidentSummary);

            return points
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(5);
        }

        private IEnumerable<AnomalySignalBarVm> BuildTopMlSignals(AnomalyVm selected)
        {
            var brushes = new Brush[]
            {
                new SolidColorBrush(Color.FromRgb(239, 68, 68)),
                new SolidColorBrush(Color.FromRgb(249, 115, 22)),
                new SolidColorBrush(Color.FromRgb(245, 158, 11)),
                new SolidColorBrush(Color.FromRgb(34, 197, 94)),
                new SolidColorBrush(Color.FromRgb(59, 130, 246))
            };

            var featureSignals = selected.FeatureMap
                .Where(kv => kv.Key.StartsWith("MlFeature:", StringComparison.OrdinalIgnoreCase) && TryParseNumber(kv.Value, out _))
                .Select(kv =>
                {
                    TryParseNumber(kv.Value, out var rawValue);
                    var percent = NormalizePercent(rawValue);
                    return new
                    {
                        Name = HumanizeFeatureKey(kv.Key),
                        Value = percent
                    };
                })
                .OrderByDescending(item => item.Value)
                .Take(5)
                .ToList();

            for (var i = 0; i < featureSignals.Count; i++)
            {
                var feature = featureSignals[i];
                yield return new AnomalySignalBarVm(
                    feature.Name,
                    feature.Value,
                    brushes[Math.Min(i, brushes.Length - 1)]);
            }
        }

        private IEnumerable<AnomalyMetricRowVm> BuildEntityHistoryRows(AnomalyVm selected, IReadOnlyList<AnomalyVm> sameHost)
        {
            if (sameHost.Count == 0)
                yield break;

            var allByHost = _vm.All
                .GroupBy(item => item.SourceLabel)
                .Where(group => !string.IsNullOrWhiteSpace(group.Key))
                .ToList();
            var timeLabel = BuildWindowLabel(sameHost);

            yield return BuildMetricRow(timeLabel, "Outbound connections", MeasureOutboundConnections(sameHost), Average(allByHost, MeasureOutboundConnections), false);
            yield return BuildMetricRow(timeLabel, "Unique destinations", MeasureUniqueDestinations(sameHost), Average(allByHost, MeasureUniqueDestinations), false);
            yield return BuildMetricRow(timeLabel, "Rule hits", MeasureRuleHits(sameHost), Average(allByHost, MeasureRuleHits), false);
            yield return BuildMetricRow(timeLabel, "DNS query volume", MeasureDnsSignals(sameHost), Average(allByHost, MeasureDnsSignals), false);
            yield return BuildMetricRow(timeLabel, "Failed auth attempts", MeasureFailedAuthSignals(sameHost), Average(allByHost, MeasureFailedAuthSignals), true);
        }

        private IEnumerable<AnomalyMetricRowVm> BuildBaselineDriftRows(AnomalyVm selected, IReadOnlyList<AnomalyVm> sameCategory)
        {
            if (sameCategory.Count == 0)
                yield break;

            var peerGroups = sameCategory
                .GroupBy(item => item.SourceLabel)
                .Where(group => !string.IsNullOrWhiteSpace(group.Key))
                .ToList();

            var selectedHostItems = sameCategory
                .Where(item => string.Equals(item.SourceLabel, selected.SourceLabel, StringComparison.OrdinalIgnoreCase))
                .ToList();

            yield return BuildMetricRow("Peer", "Outbound connections", MeasureOutboundConnections(selectedHostItems), Average(peerGroups, MeasureOutboundConnections), false);
            yield return BuildMetricRow("Peer", "Unique destinations", MeasureUniqueDestinations(selectedHostItems), Average(peerGroups, MeasureUniqueDestinations), false);
            yield return BuildMetricRow("Peer", "Rule intensity", MeasureRuleHits(selectedHostItems), Average(peerGroups, MeasureRuleHits), false);
            yield return BuildMetricRow("Peer", "DNS query volume", MeasureDnsSignals(selectedHostItems), Average(peerGroups, MeasureDnsSignals), false);
            yield return BuildMetricRow("Peer", "Failed auth rate", MeasureFailedAuthSignals(selectedHostItems), Average(peerGroups, MeasureFailedAuthSignals), true);
        }

        private AnomalyMetricRowVm BuildMetricRow(string timeLabel, string metric, double observed, double baseline, bool favorableWhenLower)
        {
            var deviation = PercentDifference(observed, baseline);
            return new AnomalyMetricRowVm(
                timeLabel,
                metric,
                FormatMetricNumber(observed),
                baseline <= 0d ? "No baseline" : FormatMetricNumber(baseline),
                FormatSignedPercent(deviation),
                BuildTrendLabel(deviation, favorableWhenLower),
                SelectDeviationBrush(deviation, favorableWhenLower));
        }

        private void UpdateQueueFooter()
        {
            if (_vm.FilteredCount == 0)
            {
                _vm.QueueCountText = "No anomalies match the current filters";
                _vm.QueuePageText = "0 / 0";
                return;
            }

            var start = ((_vm.CurrentPage - 1) * _vm.PageSize) + 1;
            var end = Math.Min(_vm.FilteredCount, start + _vm.Visible.Count - 1);
            _vm.QueueCountText = $"Showing {start}-{end} of {_vm.FilteredCount} anomalies";
            _vm.QueuePageText = $"{_vm.CurrentPage} / {_vm.TotalPages}";
        }

        private void UpdateEmptyStates()
        {
            AnomaliesEmptyState.Visibility = _vm.Visible.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            _vm.Search = SearchBox.Text ?? string.Empty;
            ApplyFilter();
        }

        private void OnlyLinkedBox_Changed(object sender, RoutedEventArgs e)
        {
            _vm.OnlyLinked = OnlyLinkedBox.IsChecked == true;
            _vm.CurrentPage = 1;
            ApplyFilter();
        }

        private void ResetFilters_Click(object sender, RoutedEventArgs e)
        {
            _suppressFilterRefresh = true;
            _vm.FilterCategory = "All categories";
            _vm.FilterSeverity = "All severities";
            _vm.Search = string.Empty;
            _vm.OnlyLinked = false;
            CategoryFilter.SelectedItem = _vm.FilterCategory;
            SeverityFilter.SelectedIndex = 0;
            SearchBox.Text = string.Empty;
            OnlyLinkedBox.IsChecked = false;
            _suppressFilterRefresh = false;
            ApplyFilter();
        }

        private void PreviousPage_Click(object sender, RoutedEventArgs e)
        {
            if (!_vm.CanPageBack)
                return;

            _vm.CurrentPage--;
            RebuildVisiblePage(false);
            UpdateQueueFooter();
        }

        private void NextPage_Click(object sender, RoutedEventArgs e)
        {
            if (!_vm.CanPageForward)
                return;

            _vm.CurrentPage++;
            RebuildVisiblePage(false);
            UpdateQueueFooter();
        }

        private void PageChip_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button button || button.Tag is not int pageNumber)
                return;

            _vm.CurrentPage = pageNumber;
            RebuildVisiblePage(false);
            UpdateQueueFooter();
        }

        private void PivotToHost_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null)
                return;

            if (_openHostIntegrity != null)
            {
                _openHostIntegrity.Invoke();
                return;
            }

            if (_openAnalytics != null)
            {
                _openAnalytics.Invoke();
                return;
            }

            SearchBox.Text = _vm.Selected.SourceLabel;
            SearchBox.Focus();
            SearchBox.SelectAll();
        }

        private void MarkExpected_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null || !_vm.Selected.HasRelatedIncident || string.IsNullOrWhiteSpace(_vm.Selected.RelatedIncidentId))
            {
                MessageBox.Show(
                    "This anomaly is not linked to an incident yet, so expected-behavior feedback cannot be stored here.",
                    "No Incident Link",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            _host.Analytics.MarkIncidentExpected(_vm.Selected.RelatedIncidentId);
        }

        private void ViewIncident_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null)
                return;

            if (_vm.Selected.HasRelatedIncident && !string.IsNullOrWhiteSpace(_vm.Selected.RelatedIncidentId) && _openIncidentWorkspace != null)
            {
                _openIncidentWorkspace.Invoke(_vm.Selected.RelatedIncidentId);
                return;
            }

            if (_openIncidentQueue != null)
            {
                _openIncidentQueue.Invoke();
                MessageBox.Show(
                    "This anomaly has not been correlated into an incident yet. The incident queue is open so you can continue triage and escalate through the live workflow.",
                    "Incident Escalation",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            MessageBox.Show(
                "This anomaly has not been correlated into an incident yet. Review raw traffic and detections first, then escalate from the incident workflow once correlation data is available.",
                "Incident Escalation",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

        private void OpenRawTraffic_Click(object sender, RoutedEventArgs e)
        {
            if (_openRawTraffic != null)
            {
                _openRawTraffic.Invoke();
                return;
            }

            Clipboard.SetText("Open Raw Traffic from Advanced / Forensics to inspect packets and flows for this anomaly.");
        }

        private void OpenRawDetections_Click(object sender, RoutedEventArgs e)
        {
            if (_openRawDetections != null)
            {
                _openRawDetections.Invoke();
                return;
            }

            Clipboard.SetText("Open Raw Detections from Advanced / Forensics to inspect rule hits for this anomaly.");
        }

        private void OpenIncidentQueue_Click(object sender, RoutedEventArgs e)
        {
            if (_openIncidentQueue != null)
            {
                _openIncidentQueue.Invoke();
                return;
            }

            Clipboard.SetText("Open Incident Queue from Security View to continue triage.");
        }

        private void CreateDetectionRule_Click(object sender, RoutedEventArgs e)
        {
            if (_openDetectionRules != null)
            {
                _openDetectionRules.Invoke();
                return;
            }

            MessageBox.Show(
                "Detection rule configuration is not wired from this workspace yet. Open Settings > Detection Rules from the sidebar.",
                "Detection Rules",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

        private void AddToWatchlist_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null)
                return;

            if (_openDetectionRules != null)
                _openDetectionRules.Invoke();

            MessageBox.Show(
                $"A dedicated anomaly watchlist workflow is not implemented yet. Opened Detection Rules so you can create suppression or governance logic for {_vm.Selected.SourceLabel}.",
                "Watchlist Status",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

        private void CopyJson_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.Selected == null)
                return;

            Clipboard.SetText(JsonSerializer.Serialize(_vm.Selected.ToExportObject(), new JsonSerializerOptions { WriteIndented = true }));
        }

        private void QueueRowMenu_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button { Tag: AnomalyVm anomaly } button)
                return;

            SelectAnomaly(anomaly.Id);
            OpenActionsMenu(button, anomaly);
        }

        private void MoreActions_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button button || _vm.Selected == null)
                return;

            OpenActionsMenu(button, _vm.Selected);
        }

        private void Page_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.F)
            {
                SearchBox.Focus();
                SearchBox.SelectAll();
                e.Handled = true;
            }
        }

        private static void ReplaceCollection<T>(ObservableCollection<T> target, IEnumerable<T> values)
        {
            target.Clear();
            foreach (var value in values)
                target.Add(value);
        }

        private void OpenActionsMenu(Button button, AnomalyVm anomaly)
        {
            var menu = new ContextMenu();
            menu.Items.Add(BuildMenuItem("Open Raw Traffic", (_, __) => OpenRawTraffic_Click(button, new RoutedEventArgs()), _vm.CanOpenRawTraffic));
            menu.Items.Add(BuildMenuItem("Query Detections", (_, __) => OpenRawDetections_Click(button, new RoutedEventArgs()), _vm.CanOpenRawDetections));
            menu.Items.Add(BuildMenuItem(_vm.IncidentActionLabel, (_, __) => ViewIncident_Click(button, new RoutedEventArgs()), _vm.CanOpenIncident));
            menu.Items.Add(BuildMenuItem("Pivot to Host", (_, __) => PivotToHost_Click(button, new RoutedEventArgs()), _vm.CanPivotToHost));
            menu.Items.Add(BuildMenuItem("Create Detection Rule", (_, __) => CreateDetectionRule_Click(button, new RoutedEventArgs()), _vm.CanOpenDetectionRules));
            menu.Items.Add(BuildMenuItem("Add to Watchlist", (_, __) => AddToWatchlist_Click(button, new RoutedEventArgs()), _vm.CanAddToWatchlist));
            menu.Items.Add(new Separator());
            menu.Items.Add(BuildMenuItem("Export Evidence Pack", (_, __) => CopyJson_Click(button, new RoutedEventArgs()), _vm.CanCopyEvidence));
            menu.PlacementTarget = button;
            menu.IsOpen = true;
        }

        private static MenuItem BuildMenuItem(string header, RoutedEventHandler onClick, bool isEnabled)
        {
            var item = new MenuItem
            {
                Header = header,
                IsEnabled = isEnabled
            };
            item.Click += onClick;
            return item;
        }

        internal static bool IsHighSeverity(AnomalyVm item)
            => string.Equals(item.Severity, "High", StringComparison.OrdinalIgnoreCase)
               || string.Equals(item.Severity, "Critical", StringComparison.OrdinalIgnoreCase);

        private static int SeverityRank(string? severity)
        {
            return severity?.ToLowerInvariant() switch
            {
                "critical" => 4,
                "high" => 3,
                "medium" => 2,
                "low" => 1,
                _ => 0
            };
        }

        private static bool LooksLikeDestinationDrift(AnomalyVm item)
        {
            var category = item.Category;
            return category.Contains("Destination", StringComparison.OrdinalIgnoreCase)
                   || category.Contains("Geo", StringComparison.OrdinalIgnoreCase)
                   || category.Contains("Port", StringComparison.OrdinalIgnoreCase)
                   || category.Contains("Dns", StringComparison.OrdinalIgnoreCase)
                   || category.Contains("TrafficVolume", StringComparison.OrdinalIgnoreCase);
        }

        private static bool HasMlFeature(AnomalyVm item, string featureName)
            => item.FeatureMap.Keys.Any(key =>
                key.StartsWith("MlFeature:", StringComparison.OrdinalIgnoreCase)
                && key.EndsWith(featureName, StringComparison.OrdinalIgnoreCase));

        private static double MeasureOutboundConnections(IEnumerable<AnomalyVm> items)
            => items.Count(item =>
                ContainsAny(item.Category, "Behavior", "Outbound", "TrafficVolume", "Destination")
                || ContainsAny(item.DisplayTitle, "outbound", "behavior")
                || ContainsAny(item.PrimaryReason, "outbound", "volume", "destination"));

        private static double MeasureUniqueDestinations(IEnumerable<AnomalyVm> items)
            => items.Select(item => item.DestinationLabel)
                .Where(value => !string.IsNullOrWhiteSpace(value) && !value.StartsWith("No destination", StringComparison.OrdinalIgnoreCase))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();

        private static double MeasureRuleHits(IEnumerable<AnomalyVm> items)
            => items.Sum(item => Math.Max(0, item.RelatedRuleIds.Count));

        private static double MeasureDnsSignals(IEnumerable<AnomalyVm> items)
            => items.Count(item =>
                ContainsAny(item.Category, "Dns")
                || item.Reasons.Any(reason => ContainsAny(reason, "dns", "resolver", "query")));

        private static double MeasureFailedAuthSignals(IEnumerable<AnomalyVm> items)
            => items.Count(item =>
                ContainsAny(item.Category, "Authentication")
                || item.Reasons.Any(reason => ContainsAny(reason, "auth", "login", "credential", "password", "failed")));

        private static string InferPeerGroup(AnomalyVm selected)
        {
            var value = $"{selected.SourceLabel} {selected.DisplayTitle} {selected.Category}".ToLowerInvariant();
            if (value.Contains("dc") || value.Contains("domain controller"))
                return "Domain Controllers";
            if (value.Contains("srv") || value.Contains("server"))
                return "Servers";
            if (value.Contains("iot") || value.Contains("camera") || value.Contains("sensor") || value.Contains("printer"))
                return "IoT Devices";
            return "Workstations";
        }

        private static Func<IEnumerable<AnomalyVm>, double> SelectPrimaryComparisonMetric(AnomalyVm selected)
        {
            if (ContainsAny(selected.Category, "Dns"))
                return MeasureDnsSignals;
            if (ContainsAny(selected.Category, "Authentication"))
                return MeasureFailedAuthSignals;
            if (LooksLikeDestinationDrift(selected))
                return MeasureUniqueDestinations;
            if (selected.RelatedRuleIds.Count > 0 || HasMlFeature(selected, "RuleHitCount") || HasMlFeature(selected, "SeverityWeightedRuleCount"))
                return MeasureRuleHits;
            return MeasureOutboundConnections;
        }

        private static string ResolvePrimaryMetricLabel(AnomalyVm selected)
        {
            if (ContainsAny(selected.Category, "Dns"))
                return "DNS anomalies";
            if (ContainsAny(selected.Category, "Authentication"))
                return "auth anomalies";
            if (LooksLikeDestinationDrift(selected))
                return "destination changes";
            if (selected.RelatedRuleIds.Count > 0 || HasMlFeature(selected, "RuleHitCount") || HasMlFeature(selected, "SeverityWeightedRuleCount"))
                return "rule bursts";
            return "outbound behavior signals";
        }

        private static bool ContainsAny(string? value, params string[] fragments)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;

            return fragments.Any(fragment => value.Contains(fragment, StringComparison.OrdinalIgnoreCase));
        }

        private static double Average<T>(IEnumerable<IGrouping<string, T>> groups, Func<IGrouping<string, T>, double> selector)
        {
            var values = groups.Select(selector).ToList();
            return values.Count == 0 ? 0d : values.Average();
        }

        private static string BuildPeerRankLabel(AnomalyVm selected, IReadOnlyList<AnomalyVm> peers)
        {
            if (peers.Count == 0)
                return "No peer comparison";

            var ordered = peers
                .Select(item => item.ScoreValue)
                .OrderByDescending(value => value)
                .ToList();

            var rank = ordered.FindIndex(value => value <= selected.ScoreValue);
            if (rank < 0)
                rank = ordered.Count - 1;

            var topPercent = Math.Max(1, (int)Math.Round(((rank + 1d) / ordered.Count) * 100d, MidpointRounding.AwayFromZero));
            return $"Top {topPercent}% of {ordered.Count} peer signals";
        }

        private static string BuildWindowLabel(IReadOnlyList<AnomalyVm> items)
        {
            if (items.Count == 0)
                return "no recent history";

            var start = items.Min(item => item.FirstSeenUtc);
            var end = items.Max(item => item.LastSeenUtc);
            return start.Date == end.Date
                ? $"{start.ToLocalTime():HH:mm} - {end.ToLocalTime():HH:mm}"
                : $"{start.ToLocalTime():MM-dd HH:mm} - {end.ToLocalTime():MM-dd HH:mm}";
        }

        private static string BuildModelSummary(AnomalyVm selected)
        {
            if (selected.FeatureMap.TryGetValue("MlModelName", out var modelName) && !string.IsNullOrWhiteSpace(modelName))
            {
                var confidenceText = selected.FeatureMap.TryGetValue("MlConfidence", out var confidence) && TryParseNumber(confidence, out var value)
                    ? $"confidence {FormatPercent(value)}"
                    : "confidence not recorded";
                return $"{modelName} flagged this host window with {confidenceText}. Review the strongest contributing signals before containment.";
            }

            if (selected.FeatureSignalCount > 0)
                return "Derived features were captured for this anomaly even though a named ML model was not recorded.";

            return "This anomaly is driven by baseline, rule, and correlation evidence rather than scored ML feature output.";
        }

        private static string BuildTrendLabel(double deviation, bool favorableWhenLower)
        {
            if (Math.Abs(deviation) < 5d)
                return "Near baseline";

            if (favorableWhenLower)
                return deviation > 0d ? "Above baseline" : "Lower than baseline";

            return deviation > 0d ? "Elevated" : "Below peer";
        }

        private static Brush SelectDeviationBrush(double deviation, bool favorableWhenLower)
        {
            if (Math.Abs(deviation) < 5d)
                return new SolidColorBrush(Color.FromRgb(186, 199, 216));

            if (favorableWhenLower)
                return deviation > 0d
                    ? new SolidColorBrush(Color.FromRgb(239, 68, 68))
                    : new SolidColorBrush(Color.FromRgb(34, 197, 94));

            return deviation > 0d
                ? new SolidColorBrush(Color.FromRgb(239, 68, 68))
                : new SolidColorBrush(Color.FromRgb(34, 197, 94));
        }

        private static double PercentDifference(double current, double baseline)
        {
            if (baseline <= 0d)
                return current <= 0d ? 0d : 100d;

            return ((current - baseline) / baseline) * 100d;
        }

        private static double NormalizePercent(double value)
        {
            var percent = value <= 1d ? value * 100d : value;
            return Math.Clamp(percent, 0d, 100d);
        }

        private static string FormatSignedPercent(double value)
        {
            if (double.IsNaN(value) || double.IsInfinity(value))
                return "0%";

            var rounded = Math.Round(value, 0, MidpointRounding.AwayFromZero);
            return rounded > 0d ? $"+{rounded:0}%" : $"{rounded:0}%";
        }

        private static string FormatMetricNumber(double value)
        {
            if (Math.Abs(value % 1d) < 0.05d)
                return Math.Round(value, 0, MidpointRounding.AwayFromZero).ToString("0", CultureInfo.InvariantCulture);

            return value.ToString("0.0", CultureInfo.InvariantCulture);
        }

        private static string FormatTime(DateTime? utc)
            => utc.HasValue ? utc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") : "pending";

        private static string CapitalizeValue(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return "Low";

            return char.ToUpperInvariant(value[0]) + value[1..].ToLowerInvariant();
        }

        private static string HumanizeFeatureKey(string key)
        {
            var value = key.Replace("MlFeature:", string.Empty, StringComparison.OrdinalIgnoreCase)
                .Replace("Ml", "ML", StringComparison.Ordinal)
                .Replace("Utc", "UTC", StringComparison.Ordinal);

            return SplitPascalCase(value) switch
            {
                "Outbound Bytes" => "Outbound volume spike",
                "Unique Destination Count" => "New destination entropy",
                "Rule Hit Count" => "Rule intensity",
                "Severity Weighted Rule Count" => "Rule intensity (weighted)",
                "New Destination Count" => "Destination novelty",
                "Threat Intel Hit Count" => "Threat-intel concentration",
                "ML Confidence" => "ML confidence",
                "ML Score" => "ML score",
                "ML Model Name" => "ML model",
                "ML Model Version" => "ML model version",
                "Window Start UTC" => "Window start",
                "Window End UTC" => "Window end",
                var text => text
            };
        }

        private static string FormatPercent(double value)
        {
            var percent = value <= 1d ? value * 100d : value;
            return $"{Math.Clamp(percent, 0d, 100d):0}%";
        }

        private static bool TryParseNumber(string? value, out double number)
        {
            number = 0d;
            if (string.IsNullOrWhiteSpace(value))
                return false;

            return double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out number)
                   || double.TryParse(value.Replace(',', '.'), NumberStyles.Float, CultureInfo.InvariantCulture, out number)
                   || double.TryParse(value, NumberStyles.Float, CultureInfo.CurrentCulture, out number);
        }

        private static string SplitPascalCase(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return value;

            var chars = new List<char>(value.Length + 8);
            for (var i = 0; i < value.Length; i++)
            {
                var c = value[i];
                if (i > 0 && char.IsUpper(c) && !char.IsWhiteSpace(value[i - 1]) && !char.IsUpper(value[i - 1]))
                    chars.Add(' ');
                chars.Add(c);
            }

            return new string(chars.ToArray()).Trim();
        }

        public sealed class IncidentLink
        {
            public string Id { get; init; } = "";
            public string Title { get; init; } = "";
            public string Status { get; init; } = "New";
            public string Severity { get; init; } = "Medium";
            public int RiskScore { get; init; }
            public string Summary { get; init; } = "";
            public IReadOnlyList<string> RecommendedActions { get; init; } = Array.Empty<string>();

            public static IncidentLink From(Incident incident)
            {
                return new IncidentLink
                {
                    Id = incident.Id,
                    Title = string.IsNullOrWhiteSpace(incident.Title) ? "Incident" : incident.Title,
                    Status = string.IsNullOrWhiteSpace(incident.Status) ? "New" : incident.Status,
                    Severity = string.IsNullOrWhiteSpace(incident.Severity) ? "Medium" : incident.Severity,
                    RiskScore = incident.RiskScore,
                    Summary = string.IsNullOrWhiteSpace(incident.Summary)
                        ? incident.RiskReasons.FirstOrDefault()
                            ?? incident.Evidence.FirstOrDefault()
                            ?? "Incident context is still being assembled."
                        : incident.Summary,
                    RecommendedActions = incident.RecommendedActions.Count == 0
                        ? Array.Empty<string>()
                        : incident.RecommendedActions.ToArray()
                };
            }
        }
    }

    public sealed class AnomaliesVm : INotifyPropertyChanged
    {
        public ObservableCollection<AnomalyVm> All { get; } = new();
        public ObservableCollection<AnomalyVm> Visible { get; } = new();
        public ObservableCollection<string> CategoryOptions { get; } = new();
        public ObservableCollection<PageChipVm> PageChips { get; } = new();
        public ObservableCollection<string> ModelExplanationPoints { get; } = new();
        public ObservableCollection<AnomalySignalBarVm> TopMlSignals { get; } = new();
        public ObservableCollection<AnomalyMetricRowVm> EntityHistoryRows { get; } = new();
        public ObservableCollection<AnomalyMetricRowVm> BaselineDriftRows { get; } = new();

        private int _rawSignalCount;
        public int RawSignalCount
        {
            get => _rawSignalCount;
            set
            {
                _rawSignalCount = Math.Max(0, value);
                OnChanged();
            }
        }

        public int NewAnomalies15m { get; private set; }
        public string NewAnomaliesDeltaText { get; private set; } = "No recent change";
        public int HighSeverityCount { get; private set; }
        public string HighSeverityDeltaText { get; private set; } = "No recent change";
        public int BehaviorDriftPercent { get; private set; }
        public string BehaviorDriftDeltaText { get; private set; } = "Stable";
        public int LinkedIncidentsCount { get; private set; }
        public string LinkedIncidentsDeltaText { get; private set; } = "No linked changes";

        private string _baselineConfidenceLabel = "Low";
        public string BaselineConfidenceLabel
        {
            get => _baselineConfidenceLabel;
            set
            {
                _baselineConfidenceLabel = string.IsNullOrWhiteSpace(value) ? "Low" : value;
                OnChanged();
            }
        }

        private string _baselineHeadline = "Baseline learning - confidence: Low";
        public string BaselineHeadline
        {
            get => _baselineHeadline;
            set
            {
                _baselineHeadline = value;
                OnChanged();
            }
        }

        private string _baselineDetail = "More observations are needed before strong anomaly scoring is available.";
        public string BaselineDetail
        {
            get => _baselineDetail;
            set
            {
                _baselineDetail = value;
                OnChanged();
            }
        }

        private string _baselineHealthText = "Learning in progress";
        public string BaselineHealthText
        {
            get => _baselineHealthText;
            set
            {
                _baselineHealthText = value;
                OnChanged();
            }
        }

        private AnomalyVm? _selected;
        public AnomalyVm? Selected
        {
            get => _selected;
            set
            {
                _selected = value;
                OnChanged();
            }
        }

        private string _filterCategory = "All categories";
        public string FilterCategory
        {
            get => _filterCategory;
            set
            {
                _filterCategory = string.IsNullOrWhiteSpace(value) ? "All categories" : value;
                OnChanged();
            }
        }

        private string _filterSeverity = "All severities";
        public string FilterSeverity
        {
            get => _filterSeverity;
            set
            {
                _filterSeverity = string.IsNullOrWhiteSpace(value) ? "All severities" : value;
                OnChanged();
            }
        }

        private string _search = "";
        public string Search
        {
            get => _search;
            set
            {
                _search = value ?? string.Empty;
                OnChanged();
            }
        }

        private bool _onlyLinked;
        public bool OnlyLinked
        {
            get => _onlyLinked;
            set
            {
                _onlyLinked = value;
                OnChanged();
            }
        }

        public int PageSize { get; } = 7;

        private int _currentPage = 1;
        public int CurrentPage
        {
            get => _currentPage;
            set
            {
                _currentPage = Math.Max(1, value);
                OnChanged();
            }
        }

        private int _totalPages = 1;
        public int TotalPages
        {
            get => _totalPages;
            set
            {
                _totalPages = Math.Max(1, value);
                OnChanged();
            }
        }

        private int _filteredCount;
        public int FilteredCount
        {
            get => _filteredCount;
            set
            {
                _filteredCount = Math.Max(0, value);
                OnChanged();
            }
        }

        private bool _canPageBack;
        public bool CanPageBack
        {
            get => _canPageBack;
            set
            {
                _canPageBack = value;
                OnChanged();
            }
        }

        private bool _canPageForward;
        public bool CanPageForward
        {
            get => _canPageForward;
            set
            {
                _canPageForward = value;
                OnChanged();
            }
        }

        private string _queueCountText = "Showing 0 anomalies";
        public string QueueCountText
        {
            get => _queueCountText;
            set
            {
                _queueCountText = value;
                OnChanged();
            }
        }

        private string _queuePageText = "0 / 0";
        public string QueuePageText
        {
            get => _queuePageText;
            set
            {
                _queuePageText = value;
                OnChanged();
            }
        }

        private string _selectedWindowLabel = "No active host";
        public string SelectedWindowLabel
        {
            get => _selectedWindowLabel;
            set
            {
                _selectedWindowLabel = value;
                OnChanged();
            }
        }

        private string _baselineStatusText = "No anomaly selected yet.";
        public string BaselineStatusText
        {
            get => _baselineStatusText;
            set
            {
                _baselineStatusText = value;
                OnChanged();
            }
        }

        private string _baselineNormalLabel = "No selection";
        public string BaselineNormalLabel
        {
            get => _baselineNormalLabel;
            set
            {
                _baselineNormalLabel = value;
                OnChanged();
            }
        }

        private string _baselineCurrentLabel = "No selection";
        public string BaselineCurrentLabel
        {
            get => _baselineCurrentLabel;
            set
            {
                _baselineCurrentLabel = value;
                OnChanged();
            }
        }

        private string _baselineDeviationLabel = "0%";
        public string BaselineDeviationLabel
        {
            get => _baselineDeviationLabel;
            set
            {
                _baselineDeviationLabel = value;
                OnChanged();
            }
        }

        private string _peerGroupLabel = "No peer group";
        public string PeerGroupLabel
        {
            get => _peerGroupLabel;
            set
            {
                _peerGroupLabel = value;
                OnChanged();
            }
        }

        private string _peerGroupHeader = "Peer group unavailable";
        public string PeerGroupHeader
        {
            get => _peerGroupHeader;
            set
            {
                _peerGroupHeader = value;
                OnChanged();
            }
        }

        private string _modelSummary = "Select an anomaly to see baseline drift, feature evidence, and next actions.";
        public string ModelSummary
        {
            get => _modelSummary;
            set
            {
                _modelSummary = value;
                OnChanged();
            }
        }

        private bool _canPivotToHost;
        public bool CanPivotToHost
        {
            get => _canPivotToHost;
            set
            {
                _canPivotToHost = value;
                OnChanged();
            }
        }

        private bool _canCopyEvidence;
        public bool CanCopyEvidence
        {
            get => _canCopyEvidence;
            set
            {
                _canCopyEvidence = value;
                OnChanged();
            }
        }

        private bool _canOpenRawTraffic;
        public bool CanOpenRawTraffic
        {
            get => _canOpenRawTraffic;
            set
            {
                _canOpenRawTraffic = value;
                OnChanged();
            }
        }

        private bool _canOpenRawDetections;
        public bool CanOpenRawDetections
        {
            get => _canOpenRawDetections;
            set
            {
                _canOpenRawDetections = value;
                OnChanged();
            }
        }

        private bool _canOpenIncidentQueue;
        public bool CanOpenIncidentQueue
        {
            get => _canOpenIncidentQueue;
            set
            {
                _canOpenIncidentQueue = value;
                OnChanged();
            }
        }

        private bool _canMarkExpected;
        public bool CanMarkExpected
        {
            get => _canMarkExpected;
            set
            {
                _canMarkExpected = value;
                OnChanged();
            }
        }

        private bool _canOpenDetectionRules;
        public bool CanOpenDetectionRules
        {
            get => _canOpenDetectionRules;
            set
            {
                _canOpenDetectionRules = value;
                OnChanged();
            }
        }

        private bool _canAddToWatchlist;
        public bool CanAddToWatchlist
        {
            get => _canAddToWatchlist;
            set
            {
                _canAddToWatchlist = value;
                OnChanged();
            }
        }

        private bool _canOpenIncident;
        public bool CanOpenIncident
        {
            get => _canOpenIncident;
            set
            {
                _canOpenIncident = value;
                OnChanged();
            }
        }

        private string _incidentActionLabel = "Escalate to Incident";
        public string IncidentActionLabel
        {
            get => _incidentActionLabel;
            set
            {
                _incidentActionLabel = string.IsNullOrWhiteSpace(value) ? "Escalate to Incident" : value;
                OnChanged();
            }
        }

        public void RefreshMetrics()
        {
            var now = DateTime.UtcNow;
            var currentCutoff = now.AddMinutes(-15);
            var previousCutoff = now.AddMinutes(-30);

            var currentWindow = All.Where(item => item.LastSeenUtc >= currentCutoff).ToList();
            var previousWindow = All.Where(item => item.LastSeenUtc >= previousCutoff && item.LastSeenUtc < currentCutoff).ToList();

            NewAnomalies15m = currentWindow.Count;
            HighSeverityCount = All.Count(AnomaliesPage.IsHighSeverity);
            LinkedIncidentsCount = All.Count(item => item.HasRelatedIncident);

            var behaviorDriftCount = All.Count(item =>
                item.Category.Contains("Behavior", StringComparison.OrdinalIgnoreCase)
                || item.Category.Contains("Volume", StringComparison.OrdinalIgnoreCase)
                || item.Category.Contains("Dns", StringComparison.OrdinalIgnoreCase)
                || item.Category.Contains("Destination", StringComparison.OrdinalIgnoreCase)
                || item.Category.Contains("Geo", StringComparison.OrdinalIgnoreCase)
                || item.Category.Contains("Port", StringComparison.OrdinalIgnoreCase)
                || item.Category.Contains("Novelty", StringComparison.OrdinalIgnoreCase));

            BehaviorDriftPercent = All.Count == 0
                ? 0
                : (int)Math.Round((behaviorDriftCount / (double)All.Count) * 100d, MidpointRounding.AwayFromZero);

            NewAnomaliesDeltaText = BuildDeltaLabel(currentWindow.Count, previousWindow.Count, "vs 15m ago");
            HighSeverityDeltaText = BuildDeltaLabel(
                currentWindow.Count(AnomaliesPage.IsHighSeverity),
                previousWindow.Count(AnomaliesPage.IsHighSeverity),
                "vs 15m ago");

            var currentBehaviorPercent = currentWindow.Count == 0
                ? 0d
                : (currentWindow.Count(item =>
                    item.Category.Contains("Behavior", StringComparison.OrdinalIgnoreCase)
                    || item.Category.Contains("Volume", StringComparison.OrdinalIgnoreCase)
                    || item.Category.Contains("Dns", StringComparison.OrdinalIgnoreCase)
                    || item.Category.Contains("Destination", StringComparison.OrdinalIgnoreCase)
                    || item.Category.Contains("Geo", StringComparison.OrdinalIgnoreCase)
                    || item.Category.Contains("Port", StringComparison.OrdinalIgnoreCase)
                    || item.Category.Contains("Novelty", StringComparison.OrdinalIgnoreCase)) / (double)currentWindow.Count) * 100d;

            var previousBehaviorPercent = previousWindow.Count == 0
                ? 0d
                : (previousWindow.Count(item =>
                    item.Category.Contains("Behavior", StringComparison.OrdinalIgnoreCase)
                    || item.Category.Contains("Volume", StringComparison.OrdinalIgnoreCase)
                    || item.Category.Contains("Dns", StringComparison.OrdinalIgnoreCase)
                    || item.Category.Contains("Destination", StringComparison.OrdinalIgnoreCase)
                    || item.Category.Contains("Geo", StringComparison.OrdinalIgnoreCase)
                    || item.Category.Contains("Port", StringComparison.OrdinalIgnoreCase)
                    || item.Category.Contains("Novelty", StringComparison.OrdinalIgnoreCase)) / (double)previousWindow.Count) * 100d;

            BehaviorDriftDeltaText = previousWindow.Count == 0
                ? "No prior window"
                : $"{FormatSignedPercent(currentBehaviorPercent - previousBehaviorPercent)} vs 15m ago";

            LinkedIncidentsDeltaText = BuildDeltaLabel(
                currentWindow.Count(item => item.HasRelatedIncident),
                previousWindow.Count(item => item.HasRelatedIncident),
                "vs 15m ago");

            OnChanged(nameof(NewAnomalies15m));
            OnChanged(nameof(NewAnomaliesDeltaText));
            OnChanged(nameof(HighSeverityCount));
            OnChanged(nameof(HighSeverityDeltaText));
            OnChanged(nameof(BehaviorDriftPercent));
            OnChanged(nameof(BehaviorDriftDeltaText));
            OnChanged(nameof(LinkedIncidentsCount));
            OnChanged(nameof(LinkedIncidentsDeltaText));
        }

        private static string BuildDeltaLabel(int current, int previous, string suffix)
        {
            var diff = current - previous;
            if (diff == 0)
                return $"0 {suffix}";

            return diff > 0 ? $"+{diff} {suffix}" : $"{diff} {suffix}";
        }

        private static string FormatSignedPercent(double value)
        {
            if (double.IsNaN(value) || double.IsInfinity(value))
                return "0%";

            var rounded = Math.Round(value, 0, MidpointRounding.AwayFromZero);
            return rounded > 0d ? $"+{rounded:0}%" : $"{rounded:0}%";
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        public void OnChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public sealed class AnomalyVm : INotifyPropertyChanged
    {
        private AnomalySignal _model = new();

        public string Id { get; private set; } = "";
        public string GroupKey { get; private set; } = "";
        public string Title { get; private set; } = "";
        public string DisplayTitle { get; private set; } = "Anomaly signal";
        public string Description { get; private set; } = "";
        public string EvidenceSummary { get; private set; } = "";
        public string Severity { get; private set; } = "Medium";
        public double ScoreValue { get; private set; }
        public string ScoreLabel => $"Score {ScoreValue:0}";
        public string ScoreNumber => ScoreValue.ToString("0", CultureInfo.InvariantCulture);
        public string SeverityUpper => Severity.ToUpperInvariant();
        public string Category { get; private set; } = "Behavior";
        public string CategoryLabel { get; private set; } = "Behavior";
        public string SourceLabel { get; private set; } = "Unknown host";
        public string DestinationLabel { get; private set; } = "No destination observed";
        public string ProtocolPortLabel { get; private set; } = "No protocol / port evidence";
        public DateTime CreatedUtc { get; private set; }
        public DateTime FirstSeenUtc { get; private set; }
        public DateTime LastSeenUtc { get; private set; }
        public string CreatedLabel => LastSeenUtc.ToLocalTime().ToString("HH:mm:ss");
        public string CreatedLabelLong => LastSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
        public string FirstSeenLabel => FirstSeenUtc == default ? CreatedLabel : FirstSeenUtc.ToLocalTime().ToString("HH:mm:ss");
        public string LastSeenLabel => LastSeenUtc == default ? CreatedLabel : LastSeenUtc.ToLocalTime().ToString("HH:mm:ss");
        public string FirstLastSeenLabel => $"{FirstSeenLabel} - {LastSeenLabel}";
        public string PrimaryReason => Reasons.FirstOrDefault() ?? "No detailed reason recorded.";
        public string DeviationSummary => RelatedRuleIds.Count > 0
            ? $"{RelatedRuleIds.First()} - {PrimaryReason}"
            : PrimaryReason;
        public string IncidentLabel { get; private set; } = "Standalone signal";
        public string RelatedIncidentId { get; private set; } = "";
        public string RelatedIncidentTitle { get; private set; } = "No correlated incident yet";
        public string RelatedIncidentStatus { get; private set; } = "Standalone";
        public string RelatedIncidentSeverity { get; private set; } = "Medium";
        public string RelatedIncidentHeadline { get; private set; } = "No correlated incident yet";
        public string RelatedIncidentSummary { get; private set; } = "This anomaly has not yet been grouped into an incident. Review the reasons and derived evidence to decide whether it should be escalated.";
        public bool HasRelatedIncident { get; private set; }
        public string QueueStatusLabel => HasRelatedIncident ? RelatedIncidentStatus : "New";
        public int OccurrenceCount { get; private set; } = 1;
        public bool HasMultipleOccurrences => OccurrenceCount > 1;
        public string OccurrenceLabel => HasMultipleOccurrences ? $"{OccurrenceCount} grouped signals" : "";
        public bool HasRelatedRuleIds => RelatedRuleIds.Count > 0;
        public bool HasEvidenceHighlights => EvidenceHighlights.Count > 0;
        public int FeatureSignalCount => FeatureMap.Count(kv => kv.Key.StartsWith("MlFeature:", StringComparison.OrdinalIgnoreCase));
        public IReadOnlyDictionary<string, string> FeatureMap => _model.Features;

        public ObservableCollection<string> Reasons { get; } = new();
        public ObservableCollection<string> RelatedRuleIds { get; } = new();
        public ObservableCollection<string> Tags { get; } = new();
        public ObservableCollection<string> FeatureLines { get; } = new();
        public ObservableCollection<string> EvidenceHighlights { get; } = new();
        public ObservableCollection<string> Guidance { get; } = new();

        public static AnomalyVm From(AnomalySignal anomaly, AnomaliesPage.IncidentLink? incidentLink)
        {
            var vm = new AnomalyVm();
            vm.UpdateFrom(anomaly, incidentLink);
            return vm;
        }

        public void UpdateFrom(AnomalySignal anomaly, AnomaliesPage.IncidentLink? incidentLink)
        {
            var previousFirstSeen = FirstSeenUtc;
            var previousLastSeen = LastSeenUtc;

            _model = anomaly ?? new AnomalySignal();

            Id = _model.Id;
            GroupKey = BuildGroupKey(_model);
            Title = string.IsNullOrWhiteSpace(_model.Title) ? "Anomaly signal" : _model.Title.Trim();
            DisplayTitle = BuildDisplayTitle(_model, Title);
            Description = string.IsNullOrWhiteSpace(_model.Description) ? "Derived anomaly evidence is available below." : _model.Description.Trim();
            EvidenceSummary = BuildEvidenceSummary(_model);
            Severity = Capitalize(_model.Severity);
            ScoreValue = NormalizeScore(_model.Score, Severity);
            Category = string.IsNullOrWhiteSpace(_model.Category) ? "Behavior" : _model.Category.Trim();
            CategoryLabel = HumanizeCategory(Category);
            SourceLabel = FriendlyValue(_model.SourceIp, "Unknown host");
            DestinationLabel = BuildDestinationLabel(_model);
            ProtocolPortLabel = BuildProtocolPortLabel(_model.Protocol, _model.DestinationPort);
            CreatedUtc = _model.CreatedUtc == default ? DateTime.UtcNow : _model.CreatedUtc;
            FirstSeenUtc = previousFirstSeen == default ? CreatedUtc : previousFirstSeen;
            LastSeenUtc = previousLastSeen == default ? CreatedUtc : previousLastSeen;
            if (CreatedUtc < FirstSeenUtc)
                FirstSeenUtc = CreatedUtc;
            if (CreatedUtc > LastSeenUtc)
                LastSeenUtc = CreatedUtc;

            if (OccurrenceCount <= 0)
                OccurrenceCount = 1;

            ReplaceCollection(Reasons,
                _model.Reasons.Count == 0
                    ? new[] { "No detailed anomaly reasons were recorded." }
                    : _model.Reasons.Select(CleanReason).Where(value => !string.IsNullOrWhiteSpace(value)));

            ReplaceCollection(RelatedRuleIds,
                _model.RelatedRuleIds
                    .Where(value => !IsPlaceholder(value))
                    .Select(value => value.Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase));

            ReplaceCollection(Tags,
                _model.Tags.Count == 0
                    ? new[] { "No tags recorded." }
                    : _model.Tags.Select(HumanizeTag).Distinct(StringComparer.OrdinalIgnoreCase));

            ReplaceCollection(FeatureLines,
                _model.Features.Count == 0
                    ? Array.Empty<string>()
                    : _model.Features
                        .OrderBy(kv => FeatureSortOrder(kv.Key))
                        .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                        .Select(FormatFeatureLine));

            ReplaceCollection(EvidenceHighlights, BuildEvidenceHighlights(_model));

            ApplyIncidentLink(incidentLink);
            RaiseAllDisplayChanges();
        }

        public void MergeFrom(AnomalySignal anomaly, AnomaliesPage.IncidentLink? incidentLink)
        {
            var nextCount = Math.Max(1, OccurrenceCount) + 1;
            var incomingUtc = anomaly.CreatedUtc == default ? DateTime.UtcNow : anomaly.CreatedUtc;
            var earliest = FirstSeenUtc == default ? incomingUtc : (incomingUtc < FirstSeenUtc ? incomingUtc : FirstSeenUtc);
            var latest = LastSeenUtc == default ? incomingUtc : (incomingUtc > LastSeenUtc ? incomingUtc : LastSeenUtc);

            if (incomingUtc >= CreatedUtc)
                UpdateFrom(anomaly, incidentLink);
            else
                ApplyIncidentLink(incidentLink);

            FirstSeenUtc = earliest;
            LastSeenUtc = latest;
            OccurrenceCount = nextCount;

            OnChanged(nameof(FirstSeenUtc));
            OnChanged(nameof(LastSeenUtc));
            OnChanged(nameof(FirstSeenLabel));
            OnChanged(nameof(LastSeenLabel));
            OnChanged(nameof(FirstLastSeenLabel));
            OnChanged(nameof(OccurrenceCount));
            OnChanged(nameof(HasMultipleOccurrences));
            OnChanged(nameof(OccurrenceLabel));
        }

        public void ApplyIncidentLink(AnomaliesPage.IncidentLink? incidentLink)
        {
            if (incidentLink is null)
            {
                HasRelatedIncident = false;
                RelatedIncidentId = string.Empty;
                IncidentLabel = "Standalone signal";
                RelatedIncidentTitle = "No correlated incident yet";
                RelatedIncidentStatus = "Standalone";
                RelatedIncidentSeverity = "Medium";
                RelatedIncidentHeadline = "No correlated incident yet";
                RelatedIncidentSummary = "This anomaly has not yet been grouped into an incident. Review the reasons and derived evidence to decide whether it should be escalated.";
                ReplaceCollection(Guidance, BuildGuidance(_model, null));
            }
            else
            {
                var link = incidentLink;
                HasRelatedIncident = true;
                RelatedIncidentId = link.Id;
                IncidentLabel = $"Incident - Risk {link.RiskScore}";
                RelatedIncidentTitle = link.Title;
                RelatedIncidentStatus = link.Status;
                RelatedIncidentSeverity = Capitalize(link.Severity);
                RelatedIncidentHeadline = $"{link.Title} - {link.Status} - {Capitalize(link.Severity)}";
                RelatedIncidentSummary = link.Summary;
                ReplaceCollection(Guidance, BuildGuidance(_model, link));
            }

            OnChanged(nameof(HasRelatedIncident));
            OnChanged(nameof(RelatedIncidentId));
            OnChanged(nameof(IncidentLabel));
            OnChanged(nameof(RelatedIncidentTitle));
            OnChanged(nameof(RelatedIncidentStatus));
            OnChanged(nameof(RelatedIncidentSeverity));
            OnChanged(nameof(RelatedIncidentHeadline));
            OnChanged(nameof(RelatedIncidentSummary));
            OnChanged(nameof(QueueStatusLabel));
        }

        public object ToExportObject() => new
        {
            Id,
            GroupKey,
            Title,
            DisplayTitle,
            Description,
            EvidenceSummary,
            Severity,
            Score = ScoreValue,
            Category,
            CategoryLabel,
            SourceLabel,
            DestinationLabel,
            ProtocolPortLabel,
            CreatedUtc,
            FirstSeenUtc,
            LastSeenUtc,
            OccurrenceCount,
            Reasons = Reasons.ToArray(),
            RelatedRuleIds = RelatedRuleIds.ToArray(),
            Tags = Tags.ToArray(),
            EvidenceHighlights = EvidenceHighlights.ToArray(),
            FeatureLines = FeatureLines.ToArray(),
            Guidance = Guidance.ToArray(),
            RelatedIncidentId,
            RelatedIncidentTitle,
            RelatedIncidentStatus,
            RelatedIncidentSeverity,
            RelatedIncidentHeadline,
            RelatedIncidentSummary
        };

        public event PropertyChangedEventHandler? PropertyChanged;

        public void OnChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

        public static string BuildGroupKey(AnomalySignal anomaly)
        {
            if (anomaly == null)
                return "unknown";

            var source = NormalizeGroupPart(anomaly.SourceIp);
            if (string.IsNullOrWhiteSpace(source))
                return $"id:{anomaly.Id}";

            var category = NormalizeGroupPart(anomaly.Category);
            var destination = NormalizeGroupPart(anomaly.DestinationHost ?? anomaly.DestinationIp);
            var protocol = NormalizeGroupPart(anomaly.Protocol);
            var port = NormalizeGroupPart(anomaly.DestinationPort);

            return $"{category}|{source}|{destination}|{protocol}|{port}";
        }

        private static IEnumerable<string> BuildGuidance(AnomalySignal anomaly, AnomaliesPage.IncidentLink? link)
        {
            if (link?.RecommendedActions.Count > 0)
                return link.RecommendedActions;

            var category = anomaly.Category?.ToLowerInvariant() ?? string.Empty;

            if (category.Contains("ml", StringComparison.Ordinal))
            {
                return new[]
                {
                    "Check whether the highlighted ML features match expected scheduled jobs, backups, scans, or update traffic for this host.",
                    "Review endpoint process context and recent destinations before containment; ML anomalies are strongest when confirmed with raw telemetry.",
                    "If the behavior is expected, tune the baseline or suppress the repeated pattern rather than ignoring the host entirely."
                };
            }

            if (category.Contains("dns", StringComparison.Ordinal))
            {
                return new[]
                {
                    "Review the queried domain, SNI, or destination host and compare it with the host's normal DNS baseline.",
                    "Check which process or service initiated the network activity if process context is available.",
                    "Confirm whether the destination is expected for this host or user."
                };
            }

            if (category.Contains("volume", StringComparison.Ordinal) || category.Contains("outbound", StringComparison.Ordinal))
            {
                return new[]
                {
                    "Confirm whether the transfer volume is expected for this host and time window.",
                    "Inspect destination ASN, country, and business context before deciding whether to isolate the host.",
                    "Review the responsible process and any related detections for signs of exfiltration or bulk scanning."
                };
            }

            if (category.Contains("reputation", StringComparison.Ordinal) || category.Contains("threatintel", StringComparison.Ordinal))
            {
                return new[]
                {
                    "Verify the destination against the configured threat feed or reputation source.",
                    "Search for other hosts contacting the same destination or sharing the same fingerprint.",
                    "If the destination is not expected, consider blocking it after confirming business impact."
                };
            }

            if (category.Contains("fingerprint", StringComparison.Ordinal))
            {
                return new[]
                {
                    "Compare the observed JA4 or HASSH fingerprint with previous behavior from the same host.",
                    "Review TLS SNI, certificate, or SSH metadata if it is available.",
                    "Check whether the destination reputation and ASN are consistent with the claimed service."
                };
            }

            if (category.Contains("port", StringComparison.Ordinal) || category.Contains("process", StringComparison.Ordinal))
            {
                return new[]
                {
                    "Confirm whether the destination port or initiating process is expected for this host.",
                    "Look for other recent anomalies from the same source to decide whether this is a broader behavior change.",
                    "Validate the service owner before suppressing or allowlisting the pattern."
                };
            }

            return new[]
            {
                "Review the source host, destination, and recent anomaly history together before concluding that the behavior is benign.",
                "Check whether related raw detections or raw traffic in Advanced / Forensics provide more context.",
                "If this pattern repeats or links to additional anomalies, escalate it into the incident queue."
            };
        }

        private void RaiseAllDisplayChanges()
        {
            OnChanged(nameof(Id));
            OnChanged(nameof(GroupKey));
            OnChanged(nameof(Title));
            OnChanged(nameof(DisplayTitle));
            OnChanged(nameof(Description));
            OnChanged(nameof(EvidenceSummary));
            OnChanged(nameof(Severity));
            OnChanged(nameof(ScoreValue));
            OnChanged(nameof(ScoreLabel));
            OnChanged(nameof(ScoreNumber));
            OnChanged(nameof(SeverityUpper));
            OnChanged(nameof(Category));
            OnChanged(nameof(CategoryLabel));
            OnChanged(nameof(SourceLabel));
            OnChanged(nameof(DestinationLabel));
            OnChanged(nameof(ProtocolPortLabel));
            OnChanged(nameof(CreatedUtc));
            OnChanged(nameof(CreatedLabel));
            OnChanged(nameof(CreatedLabelLong));
            OnChanged(nameof(FirstSeenUtc));
            OnChanged(nameof(LastSeenUtc));
            OnChanged(nameof(FirstSeenLabel));
            OnChanged(nameof(LastSeenLabel));
            OnChanged(nameof(FirstLastSeenLabel));
            OnChanged(nameof(PrimaryReason));
            OnChanged(nameof(DeviationSummary));
            OnChanged(nameof(OccurrenceCount));
            OnChanged(nameof(HasMultipleOccurrences));
            OnChanged(nameof(OccurrenceLabel));
            OnChanged(nameof(HasRelatedRuleIds));
            OnChanged(nameof(HasEvidenceHighlights));
            OnChanged(nameof(QueueStatusLabel));
            OnChanged(nameof(FeatureSignalCount));
        }

        private static double NormalizeScore(double rawScore, string severity)
        {
            var floor = severity switch
            {
                "Critical" => 90d,
                "High" => 75d,
                "Medium" => 45d,
                "Low" => 15d,
                _ => 25d
            };

            if (double.IsNaN(rawScore) || double.IsInfinity(rawScore) || rawScore <= 0d)
                return floor;

            var normalized = rawScore <= 1d
                ? rawScore * 100d
                : rawScore <= 10d
                    ? rawScore * 10d
                    : rawScore;

            normalized = Math.Clamp(normalized, 0d, 100d);
            return Math.Max(normalized, floor);
        }

        private static string BuildDisplayTitle(AnomalySignal model, string title)
        {
            var category = model.Category ?? string.Empty;
            if (category.Contains("ml", StringComparison.OrdinalIgnoreCase))
                return "ML-assisted behavior anomaly";

            const string suffixMarker = " for ";
            var idx = title.IndexOf(suffixMarker, StringComparison.OrdinalIgnoreCase);
            return idx > 12 && title.Length - idx > 16
                ? title[..idx].Trim()
                : title;
        }

        private static string BuildEvidenceSummary(AnomalySignal model)
        {
            if (model.Features.Count == 0)
                return "Evidence is based on recent detections and baseline comparison.";

            var parts = new List<string>();
            if (model.Features.TryGetValue("MlModelName", out var modelName) && !string.IsNullOrWhiteSpace(modelName))
            {
                var version = model.Features.TryGetValue("MlModelVersion", out var v) && !string.IsNullOrWhiteSpace(v)
                    ? $" v{v}"
                    : string.Empty;
                parts.Add($"Model {modelName}{version}");
            }

            if (model.Features.TryGetValue("MlConfidence", out var confidence) && TryParseNumber(confidence, out var confidenceValue))
                parts.Add($"confidence {FormatPercent(confidenceValue)}");

            if (model.Features.TryGetValue("WindowStartUtc", out var start) && model.Features.TryGetValue("WindowEndUtc", out var end)
                && DateTime.TryParse(start, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var startUtc)
                && DateTime.TryParse(end, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var endUtc))
            {
                parts.Add($"window {startUtc.ToLocalTime():HH:mm:ss}-{endUtc.ToLocalTime():HH:mm:ss}");
            }

            return parts.Count == 0
                ? "Derived features are available for analyst review."
                : string.Join(" | ", parts);
        }

        private static IEnumerable<string> BuildEvidenceHighlights(AnomalySignal model)
        {
            if (model.Features.Count == 0)
                return Array.Empty<string>();

            var highlights = new List<string>();

            if (model.Features.TryGetValue("MlModelName", out var modelName) && !string.IsNullOrWhiteSpace(modelName))
            {
                var version = model.Features.TryGetValue("MlModelVersion", out var v) && !string.IsNullOrWhiteSpace(v)
                    ? $" v{v}"
                    : string.Empty;
                highlights.Add($"ML model: {modelName}{version}");
            }

            if (model.Features.TryGetValue("MlConfidence", out var confidence) && TryParseNumber(confidence, out var confidenceValue))
                highlights.Add($"ML confidence: {FormatPercent(confidenceValue)}");

            if (model.Features.TryGetValue("MlScore", out var score) && TryParseNumber(score, out var scoreValue))
                highlights.Add($"ML score: {FormatScore(scoreValue)}/100");

            var topFeatures = model.Features
                .Where(kv => kv.Key.StartsWith("MlFeature:", StringComparison.OrdinalIgnoreCase))
                .Select(kv => new { Name = HumanizeFeatureKey(kv.Key), Value = TryParseNumber(kv.Value, out var parsed) ? parsed : 0d })
                .OrderByDescending(item => item.Value)
                .Take(3);

            foreach (var feature in topFeatures)
                highlights.Add($"{feature.Name}: {FormatScore(feature.Value)}/100");

            if (model.Features.TryGetValue("WindowStartUtc", out var start) && model.Features.TryGetValue("WindowEndUtc", out var end)
                && DateTime.TryParse(start, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var startUtc)
                && DateTime.TryParse(end, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var endUtc))
            {
                highlights.Add($"Analysis window: {startUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} - {endUtc.ToLocalTime():HH:mm:ss}");
            }

            return highlights;
        }

        private static string BuildDestinationLabel(AnomalySignal model)
        {
            var destination = model.DestinationHost ?? model.DestinationIp;
            return string.IsNullOrWhiteSpace(destination) || destination.Contains("unknown", StringComparison.OrdinalIgnoreCase)
                ? "No destination observed"
                : destination.Trim();
        }

        private static string BuildProtocolPortLabel(string? protocol, string? destinationPort)
        {
            var hasProtocol = !string.IsNullOrWhiteSpace(protocol) && !protocol.Contains("unknown", StringComparison.OrdinalIgnoreCase);
            var hasPort = !string.IsNullOrWhiteSpace(destinationPort) && !destinationPort.Contains("unknown", StringComparison.OrdinalIgnoreCase);

            if (!hasProtocol && !hasPort)
                return "No protocol / port evidence";

            var proto = hasProtocol ? protocol!.Trim().ToUpperInvariant() : "Unknown protocol";
            return hasPort ? $"{proto} / {destinationPort}" : proto;
        }

        private static string Capitalize(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return "Medium";

            return char.ToUpperInvariant(value[0]) + value[1..].ToLowerInvariant();
        }

        private static string CleanReason(string? reason)
        {
            if (string.IsNullOrWhiteSpace(reason))
                return string.Empty;

            var value = reason.Trim();
            value = value.Replace("ML.NET detected ", string.Empty, StringComparison.OrdinalIgnoreCase);
            value = value.Replace("compared with recent host activity", "compared with the recent host baseline", StringComparison.OrdinalIgnoreCase);

            return char.ToUpperInvariant(value[0]) + value[1..];
        }

        private static string FriendlyValue(string? value, string fallback)
        {
            return string.IsNullOrWhiteSpace(value) || value.Contains("unknown", StringComparison.OrdinalIgnoreCase)
                ? fallback
                : value.Trim();
        }

        private static string HumanizeCategory(string category)
        {
            if (string.IsNullOrWhiteSpace(category))
                return "Behavior";

            return category switch
            {
                "MlBehaviorAnomaly" => "ML behavior anomaly",
                "BehaviorChange" => "Behavior change",
                "NetworkBehavior" => "Network behavior",
                "NewDestination" => "New destination",
                "CommandAndControl" => "Command and control",
                _ => SplitPascalCase(category).Replace("Ml", "ML", StringComparison.Ordinal)
            };
        }

        private static string HumanizeFeatureKey(string key)
        {
            var value = key.Replace("MlFeature:", string.Empty, StringComparison.OrdinalIgnoreCase)
                .Replace("Ml", "ML", StringComparison.Ordinal)
                .Replace("Utc", "UTC", StringComparison.Ordinal);

            return SplitPascalCase(value) switch
            {
                "Rule Hit Count" => "Rule-hit count",
                "Severity Weighted Rule Count" => "Severity-weighted detections",
                "Unique Destination Count" => "Destination fan-out",
                "ML Confidence" => "ML confidence",
                "ML Score" => "ML score",
                "ML Model Name" => "ML model",
                "ML Model Version" => "ML model version",
                "Window Start UTC" => "Window start",
                "Window End UTC" => "Window end",
                var text => text
            };
        }

        private static string HumanizeTag(string tag)
        {
            if (string.IsNullOrWhiteSpace(tag))
                return "untagged";

            return tag.Trim().ToLowerInvariant() switch
            {
                "ml" => "ML",
                "ml-assisted" => "ML-assisted",
                "host-baseline" => "Host baseline",
                "behavior" => "Behavior",
                "anomaly" => "Anomaly",
                var value => SplitPascalCase(value.Replace('-', ' '))
            };
        }

        private static string FormatFeatureLine(KeyValuePair<string, string> feature)
            => $"{HumanizeFeatureKey(feature.Key)}: {FormatFeatureValue(feature.Key, feature.Value)}";

        private static string FormatFeatureValue(string key, string value)
        {
            if ((key.Contains("Utc", StringComparison.OrdinalIgnoreCase) || key.Contains("Window", StringComparison.OrdinalIgnoreCase))
                && DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var utc))
                return utc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

            if (TryParseNumber(value, out var number))
            {
                if (key.Contains("Confidence", StringComparison.OrdinalIgnoreCase))
                    return FormatPercent(number);

                if (key.Contains("Score", StringComparison.OrdinalIgnoreCase) || key.Contains("MlFeature", StringComparison.OrdinalIgnoreCase))
                    return $"{FormatScore(number)}/100";
            }

            return value;
        }

        private static string FormatPercent(double value)
        {
            var percent = value <= 1d ? value * 100d : value;
            return $"{Math.Clamp(percent, 0d, 100d):0}%";
        }

        private static string FormatScore(double value)
        {
            var score = value <= 1d ? value * 100d : value;
            return Math.Clamp(score, 0d, 100d).ToString("0", CultureInfo.InvariantCulture);
        }

        private static bool TryParseNumber(string? value, out double number)
        {
            number = 0d;
            if (string.IsNullOrWhiteSpace(value))
                return false;

            return double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out number)
                   || double.TryParse(value.Replace(',', '.'), NumberStyles.Float, CultureInfo.InvariantCulture, out number)
                   || double.TryParse(value, NumberStyles.Float, CultureInfo.CurrentCulture, out number);
        }

        private static int FeatureSortOrder(string key)
        {
            if (key.StartsWith("MlModelName", StringComparison.OrdinalIgnoreCase)) return 0;
            if (key.StartsWith("MlModelVersion", StringComparison.OrdinalIgnoreCase)) return 1;
            if (key.StartsWith("MlConfidence", StringComparison.OrdinalIgnoreCase)) return 2;
            if (key.StartsWith("MlScore", StringComparison.OrdinalIgnoreCase)) return 3;
            if (key.StartsWith("MlFeature:", StringComparison.OrdinalIgnoreCase)) return 4;
            if (key.StartsWith("WindowStart", StringComparison.OrdinalIgnoreCase)) return 5;
            if (key.StartsWith("WindowEnd", StringComparison.OrdinalIgnoreCase)) return 6;
            return 10;
        }

        private static bool IsPlaceholder(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return true;

            return value.Contains("no related rule", StringComparison.OrdinalIgnoreCase)
                   || value.Contains("not recorded", StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizeGroupPart(string? value)
        {
            return string.IsNullOrWhiteSpace(value) || value.Contains("unknown", StringComparison.OrdinalIgnoreCase)
                ? string.Empty
                : value.Trim().ToLowerInvariant();
        }

        private static string SplitPascalCase(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return value;

            var chars = new List<char>(value.Length + 8);
            for (var i = 0; i < value.Length; i++)
            {
                var c = value[i];
                if (i > 0 && char.IsUpper(c) && !char.IsWhiteSpace(value[i - 1]) && !char.IsUpper(value[i - 1]))
                    chars.Add(' ');
                chars.Add(c);
            }

            return new string(chars.ToArray()).Trim();
        }

        private static void ReplaceCollection(ObservableCollection<string> target, IEnumerable<string> values)
        {
            target.Clear();
            foreach (var value in values.Where(value => !string.IsNullOrWhiteSpace(value)))
                target.Add(value);
        }
    }

    public sealed class PageChipVm : INotifyPropertyChanged
    {
        public PageChipVm(int pageNumber, string label, bool isCurrent)
        {
            PageNumber = pageNumber;
            Label = label;
            _isCurrent = isCurrent;
        }

        public int PageNumber { get; }
        public string Label { get; }

        private bool _isCurrent;
        public bool IsCurrent
        {
            get => _isCurrent;
            set
            {
                _isCurrent = value;
                OnChanged();
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public sealed class AnomalySignalBarVm
    {
        public AnomalySignalBarVm(string name, double valuePercent, Brush barBrush)
        {
            Name = name;
            ValuePercent = Math.Clamp(valuePercent, 0d, 100d);
            ValueLabel = (ValuePercent / 100d).ToString("0.00", CultureInfo.InvariantCulture);
            BarWidth = 24d + (ValuePercent * 1.55d);
            BarBrush = barBrush;
        }

        public string Name { get; }
        public double ValuePercent { get; }
        public string ValueLabel { get; }
        public double BarWidth { get; }
        public Brush BarBrush { get; }
    }

    public sealed class AnomalyMetricRowVm
    {
        public AnomalyMetricRowVm(
            string timeLabel,
            string metric,
            string observed,
            string baseline,
            string deviation,
            string trend,
            Brush deviationBrush)
        {
            TimeLabel = timeLabel;
            Metric = metric;
            Observed = observed;
            Baseline = baseline;
            Deviation = deviation;
            Trend = trend;
            DeviationBrush = deviationBrush;
        }

        public string TimeLabel { get; }
        public string Metric { get; }
        public string Observed { get; }
        public string Baseline { get; }
        public string Deviation { get; }
        public string Trend { get; }
        public Brush DeviationBrush { get; }
    }
}
