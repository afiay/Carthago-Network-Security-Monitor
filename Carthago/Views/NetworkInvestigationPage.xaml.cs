// SPDX-License-Identifier: MIT
// File: Views/NetworkInvestigationPage.xaml.cs
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Carthago.Analytics.Models;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Views
{
    public partial class NetworkInvestigationPage : UserControl
    {
        private const int MaximumSessionHistory = 20;
        private static readonly NetworkBoundaryProfile LocalAddressDefaults = NetworkBoundaryProfile.DefaultLocal();
        private Incident[] _cachedIncidentCases = Array.Empty<Incident>();
        private DetectionEvent[] _cachedDetectionEvents = Array.Empty<DetectionEvent>();
        private readonly List<InvestigationHistoryEntry> _sessionHistory = new();
        private int _sessionHistoryIndex = -1;
        private int? _pendingHistoryIndex;
        private string _executedSearchTerm = string.Empty;

        private sealed class InvestigationHistoryEntry
        {
            public InvestigationHistoryEntry(string term) => Term = term;
            public string Term { get; }
            public Guid? SelectedTrafficId { get; set; }
            public string? SelectedDetectionId { get; set; }
            public string? SelectedIncidentId { get; set; }
        }

        public event RoutedEventHandler? SearchRequested;
        public event RoutedEventHandler? TrafficRequested;
        public event RoutedEventHandler? DetectionsRequested;
        public event RoutedEventHandler? AnalyticsRequested;
        public event RoutedEventHandler? IncidentQueueRequested;
        public event RoutedEventHandler? DetectionRulesRequested;
        public event Action<string>? IncidentRequested;

        public string SearchTerm => InvestigationSearchText.Text.Trim();
        public string CurrentHistoryTerm => _sessionHistoryIndex >= 0
            ? _sessionHistory[_sessionHistoryIndex].Term : SearchTerm;

        public NetworkInvestigationPage()
        {
            InitializeComponent();
            RefreshSavedSearches();
        }

        private void RefreshSavedSearches(string? selectedTerm = null)
        {
            var queries = PreferencesService.Current.SavedInvestigationQueries;
            var previouslySelected = selectedTerm ?? SavedSearches.SelectedItem as string;
            SavedSearches.ItemsSource = queries.ToArray();
            SavedSearches.SelectedItem = queries.FirstOrDefault(query =>
                string.Equals(query, previouslySelected, StringComparison.OrdinalIgnoreCase));
            SavedSearchStatusText.Text = $"{queries.Count} saved local queries (maximum 10). " +
                "IP addresses, hostnames and other search text are stored in this computer's application preferences only when you click Save current. Remove individual queries here.";
        }

        private void SaveCurrentSearch_Click(object sender, RoutedEventArgs e)
        {
            var term = SearchTerm;
            if (term.Length is < 1 or > 128)
            {
                SavedSearchStatusText.Text = "Enter a search between 1 and 128 characters before saving it.";
                return;
            }

            try
            {
                PreferencesService.Update(preferences =>
                {
                    preferences.SavedInvestigationQueries.RemoveAll(query =>
                        string.Equals(query, term, StringComparison.OrdinalIgnoreCase));
                    preferences.SavedInvestigationQueries.Insert(0, term);
                });
                RefreshSavedSearches(term);
            }
            catch (Exception ex)
            {
                SavedSearchStatusText.Text = $"Could not save search locally: {ex.Message}";
            }
        }

        private void OpenSavedSearch_Click(object sender, RoutedEventArgs e)
        {
            if (SavedSearches.SelectedItem is not string saved)
                return;

            InvestigationSearchText.Text = saved;
            SearchRequested?.Invoke(this, new RoutedEventArgs());
        }

        private void RemoveSavedSearch_Click(object sender, RoutedEventArgs e)
        {
            if (SavedSearches.SelectedItem is not string saved)
                return;

            if (MessageBox.Show("Remove this locally saved investigation query?",
                "Remove saved search", MessageBoxButton.YesNo, MessageBoxImage.Question,
                MessageBoxResult.No) != MessageBoxResult.Yes)
                return;

            try
            {
                PreferencesService.Update(preferences =>
                    preferences.SavedInvestigationQueries.RemoveAll(query =>
                        string.Equals(query, saved, StringComparison.OrdinalIgnoreCase)));
                RefreshSavedSearches();
            }
            catch (Exception ex)
            {
                SavedSearchStatusText.Text = $"Could not remove saved search: {ex.Message}";
            }
        }

        public void UpdateSnapshot(
            IEnumerable<TrafficRecord> traffic,
            IEnumerable<DetectionEvent> detections,
            IEnumerable<Incident> incidents,
            string? searchTerm)
        {
            var term = (searchTerm ?? string.Empty).Trim();
            _executedSearchTerm = term;
            var historyEntry = RecordSessionHistory(term);
            InvestigationSearchText.Text = term;
            var trafficSnapshot = traffic.Take(200).ToArray();
            var detectionSnapshot = detections.Take(500).ToArray();
            var incidentSnapshot = incidents.Take(250).ToArray();
            _cachedIncidentCases = incidentSnapshot;
            _cachedDetectionEvents = detectionSnapshot;
            var isAddress = IPAddress.TryParse(term, out _);
            var isPortQuery = !isAddress && TryParsePortQuery(term, out _);
            string searchedEventId = string.Empty;
            var isEventQuery = term.StartsWith("event:", StringComparison.OrdinalIgnoreCase);
            var isValidEventQuery = isEventQuery && TryParseEventQuery(term, out searchedEventId);

            var trafficMatches = trafficSnapshot.Where(r =>
                term.Length == 0 || TrafficMatchFields(r, term).Count > 0)
                .ToArray();
            var detectionMatches = detectionSnapshot.Where(d =>
                term.Length == 0 || DetectionMatchFields(d, term).Count > 0)
                .ToArray();

            // These are actual incident-cache entries, not incidents inferred
            // from a traffic IP match. Port-only queries do not match cases.
            var incidentMatches = incidentSnapshot.Where(incident =>
                IncidentMatchFields(incident, term).Count > 0)
                .ToArray();

            InvestigationTrafficGrid.ItemsSource = trafficMatches;
            InvestigationDetectionsGrid.ItemsSource = detectionMatches;
            InvestigationIncidentsGrid.ItemsSource = incidentMatches;
            InvestigationTrafficGrid.SelectedItem = null;
            InvestigationDetectionsGrid.SelectedItem = null;
            InvestigationIncidentsGrid.SelectedItem = null;
            // A refreshed bounded snapshot must not leave details from an older
            // selection visible after the underlying grid has been replaced.
            SetEvidenceInspector(TrafficEvidenceExpander, TrafficEvidenceFields, "Selected traffic evidence · choose a row above", null);
            SetEvidenceInspector(DetectionEvidenceExpander, DetectionEvidenceFields, "Selected detection evidence · choose a row above", null);
            SetEvidenceInspector(IncidentEvidenceExpander, IncidentEvidenceFields, "Selected incident case context · choose a row above", null);
            ClearExactLinks();
            RestoreSessionSelection(historyEntry,
                trafficSnapshot, detectionSnapshot, incidentSnapshot,
                trafficMatches, detectionMatches, incidentMatches);
            if (isValidEventQuery && InvestigationDetectionsGrid.SelectedItem is null && detectionMatches.Length == 1)
            {
                // Exact-ID pivots select the actual retained event, making its
                // evidence and case references immediately accessible.
                InvestigationDetectionsGrid.SelectedItem = detectionMatches[0];
                InvestigationDetectionsGrid.ScrollIntoView(detectionMatches[0]);
            }
            UpdateMatchNavigationControls();
            TrafficCountText.Text = $"{trafficMatches.Length:N0} matching retained records";
            DetectionCountText.Text = isEventQuery && !isValidEventQuery
                ? "Invalid event ID · no detection lookup performed"
                : $"{detectionMatches.Length:N0} matching retained detections";
            IncidentCountText.Text = isEventQuery && !isValidEventQuery
                ? "Invalid event ID · no case lookup performed"
                : term.Length == 0
                ? $"Enter an incident ID, IP or case title to search up to {incidentSnapshot.Length:N0} cached cases"
                : $"{incidentMatches.Length:N0} matching cached incidents (up to {incidentSnapshot.Length:N0} checked{(isEventQuery ? "; explicit event-ID references only" : string.Empty)})";
            ScopeText.Text = isEventQuery && !isValidEventQuery
                ? "Invalid event: query. Supply an exact event ID between 1 and 128 characters after the colon."
                : term.Length == 0
                ? $"Local snapshot: {trafficSnapshot.Length:N0} traffic rows and {detectionSnapshot.Length:N0} detection events · showing all retained items"
                : $"Local snapshot: {trafficSnapshot.Length:N0} traffic rows and {detectionSnapshot.Length:N0} detection events · {(isEventQuery ? "exact event ID" : isAddress ? "exact IP" : isPortQuery ? "exact source/destination port" : "recorded text")} match for '{term}'";
        }

        private InvestigationHistoryEntry RecordSessionHistory(string term)
        {
            RememberSelectedRecords();
            if (_pendingHistoryIndex is int pending && pending >= 0 && pending < _sessionHistory.Count &&
                string.Equals(_sessionHistory[pending].Term, term, StringComparison.Ordinal))
            {
                _sessionHistoryIndex = pending;
            }
            else if (_sessionHistoryIndex < 0 ||
                     !string.Equals(_sessionHistory[_sessionHistoryIndex].Term, term, StringComparison.Ordinal))
            {
                if (_sessionHistoryIndex + 1 < _sessionHistory.Count)
                    _sessionHistory.RemoveRange(_sessionHistoryIndex + 1, _sessionHistory.Count - _sessionHistoryIndex - 1);
                _sessionHistory.Add(new InvestigationHistoryEntry(term));
                if (_sessionHistory.Count > MaximumSessionHistory)
                    _sessionHistory.RemoveAt(0);
                _sessionHistoryIndex = _sessionHistory.Count - 1;
            }

            _pendingHistoryIndex = null;
            UpdateSessionHistoryControls();
            return _sessionHistory[_sessionHistoryIndex];
        }

        private void RememberSelectedRecords()
        {
            if (_sessionHistoryIndex < 0 || _sessionHistoryIndex >= _sessionHistory.Count)
                return;

            var entry = _sessionHistory[_sessionHistoryIndex];
            var trafficId = (InvestigationTrafficGrid.SelectedItem as TrafficRecord)?.Id;
            entry.SelectedTrafficId = trafficId is Guid id && id != Guid.Empty ? id : null;
            entry.SelectedDetectionId = (InvestigationDetectionsGrid.SelectedItem as DetectionEvent)?.EventId;
            entry.SelectedIncidentId = (InvestigationIncidentsGrid.SelectedItem as Incident)?.Id;
        }

        private void RestoreSessionSelection(InvestigationHistoryEntry entry,
            IReadOnlyList<TrafficRecord> allTraffic, IReadOnlyList<DetectionEvent> allDetections,
            IReadOnlyList<Incident> allIncidents,
            IReadOnlyList<TrafficRecord> matchingTraffic, IReadOnlyList<DetectionEvent> matchingDetections,
            IReadOnlyList<Incident> matchingIncidents)
        {
            bool missing = false;

            if (entry.SelectedTrafficId is Guid trafficId)
            {
                var uniqueInSnapshot = allTraffic.Count(row => row.Id == trafficId) == 1;
                var selected = matchingTraffic.FirstOrDefault(row => row.Id == trafficId);
                if (!uniqueInSnapshot || selected is null) missing = true;
                else
                {
                    InvestigationTrafficGrid.SelectedItem = selected;
                }
            }

            if (!string.IsNullOrWhiteSpace(entry.SelectedDetectionId))
            {
                var uniqueInSnapshot = allDetections.Count(row =>
                    string.Equals(row.EventId, entry.SelectedDetectionId, StringComparison.OrdinalIgnoreCase)) == 1;
                var selected = matchingDetections.FirstOrDefault(row =>
                    string.Equals(row.EventId, entry.SelectedDetectionId, StringComparison.OrdinalIgnoreCase));
                if (!uniqueInSnapshot || selected is null) missing = true;
                else
                {
                    InvestigationDetectionsGrid.SelectedItem = selected;
                }
            }

            if (!string.IsNullOrWhiteSpace(entry.SelectedIncidentId))
            {
                var uniqueInSnapshot = allIncidents.Count(row =>
                    string.Equals(row.Id, entry.SelectedIncidentId, StringComparison.OrdinalIgnoreCase)) == 1;
                var selected = matchingIncidents.FirstOrDefault(row =>
                    string.Equals(row.Id, entry.SelectedIncidentId, StringComparison.OrdinalIgnoreCase));
                if (!uniqueInSnapshot || selected is null) missing = true;
                else
                {
                    InvestigationIncidentsGrid.SelectedItem = selected;
                }
            }

            if (missing)
                InvestigationHistoryStatusText.Text += " · Some selected records are unavailable or have ambiguous IDs in this snapshot";
        }

        private void UpdateSessionHistoryControls()
        {
            InvestigationBackButton.IsEnabled = _sessionHistoryIndex > 0;
            InvestigationForwardButton.IsEnabled = _sessionHistoryIndex >= 0 &&
                                                  _sessionHistoryIndex < _sessionHistory.Count - 1;
            ClearInvestigationHistoryButton.IsEnabled = _sessionHistory.Count > 1 ||
                (_sessionHistory.Count == 1 && _sessionHistory[0].Term.Length > 0);
            InvestigationHistoryStatusText.Text = _sessionHistoryIndex < 0
                ? "Session history is empty · no searches saved automatically"
                : _sessionHistory.Count == 1 && _sessionHistory[0].Term.Length == 0
                ? "Fresh blank investigation · no previous session steps; nothing saved automatically"
                : $"Investigation {_sessionHistoryIndex + 1:N0} of {_sessionHistory.Count:N0} · up to {MaximumSessionHistory} local session steps; nothing is saved to disk automatically";
        }

        private void MoveSessionHistory(int direction)
        {
            var next = _sessionHistoryIndex + direction;
            if (next < 0 || next >= _sessionHistory.Count)
                return;

            _pendingHistoryIndex = next;
            InvestigationSearchText.Text = _sessionHistory[next].Term;
            SearchRequested?.Invoke(this, new RoutedEventArgs());
        }

        private void InvestigationBack_Click(object sender, RoutedEventArgs e) => MoveSessionHistory(-1);
        private void InvestigationForward_Click(object sender, RoutedEventArgs e) => MoveSessionHistory(1);

        private void ClearInvestigationHistory_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show("Clear this session's investigation history and reset the explorer? Locally saved bookmarks will not be removed.",
                "Clear investigation history", MessageBoxButton.YesNo, MessageBoxImage.Question,
                MessageBoxResult.No) != MessageBoxResult.Yes)
                return;

            _sessionHistory.Clear();
            _sessionHistoryIndex = -1;
            _pendingHistoryIndex = null;
            InvestigationSearchText.Text = string.Empty;
            SearchRequested?.Invoke(this, new RoutedEventArgs());
        }

        private static bool TryParseEventQuery(string term, out string eventId)
        {
            eventId = string.Empty;
            if (!term.StartsWith("event:", StringComparison.OrdinalIgnoreCase))
                return false;
            eventId = term[6..].Trim();
            return eventId.Length is >= 1 and <= 128;
        }

        private static bool TryParsePortQuery(string term, out int port)
        {
            port = 0;
            return term.StartsWith("port:", StringComparison.OrdinalIgnoreCase)
                && int.TryParse(term.AsSpan(5).Trim(), out port)
                && port is >= 1 and <= 65535;
        }

        private static bool MatchesAddress(string? value, IPAddress searchedAddress)
            => IPAddress.TryParse(value, out var parsed) && parsed.Equals(searchedAddress);

        private static bool Contains(string? value, string text)
            => value?.Contains(text, StringComparison.OrdinalIgnoreCase) == true;

        // Read-only search of already retained traffic metadata. DNS question
        // names were present in the evidence inspector but missing from the
        // Explorer's general hostname text search (SOC-16).
        internal static bool MatchesTrafficText(TrafficRecord record, string term)
            => term.Length > 0 &&
               (Contains(record.Source, term) || Contains(record.Destination, term) ||
                Contains(record.Protocol, term) || Contains(record.ApplicationService, term) ||
                Contains(record.ProcessName, term) || Contains(record.WhoisCountry, term) ||
                Contains(record.Sni, term) || Contains(record.HttpHost, term) ||
                Contains(record.DnsQname, term));

        // Return field names, never values, so the explanation does not create
        // a new path for displaying unreviewed or sensitive evidence.
        internal static IReadOnlyList<string> TrafficMatchFields(TrafficRecord row, string term)
        {
            var fields = new List<string>();
            if (string.IsNullOrWhiteSpace(term) || term.StartsWith("event:", StringComparison.OrdinalIgnoreCase))
                return fields;
            term = term.Trim();
            if (IPAddress.TryParse(term, out var ip))
            {
                AddExactIp(fields, "Source IP", row.Source, ip);
                AddExactIp(fields, "Destination IP", row.Destination, ip);
            }
            else if (TryParsePortQuery(term, out var port))
            {
                if (row.SourcePort == port) fields.Add("Source port (exact)");
                if (row.DestinationPort == port) fields.Add("Destination port (exact)");
            }
            else
            {
                AddTextMatch(fields, "Source", row.Source, term);
                AddTextMatch(fields, "Destination", row.Destination, term);
                AddTextMatch(fields, "Protocol", row.Protocol, term);
                AddTextMatch(fields, "Application service", row.ApplicationService, term);
                AddTextMatch(fields, "Process name", row.ProcessName, term);
                AddTextMatch(fields, "WHOIS country", row.WhoisCountry, term);
                AddTextMatch(fields, "TLS SNI", row.Sni, term);
                AddTextMatch(fields, "HTTP host", row.HttpHost, term);
                AddTextMatch(fields, "DNS question", row.DnsQname, term);
            }
            return fields;
        }

        internal static IReadOnlyList<string> DetectionMatchFields(DetectionEvent row, string term)
        {
            var fields = new List<string>();
            if (string.IsNullOrWhiteSpace(term)) return fields;
            term = term.Trim();
            if (term.StartsWith("event:", StringComparison.OrdinalIgnoreCase))
            {
                if (TryParseEventQuery(term, out var id) && string.Equals(row.EventId, id, StringComparison.OrdinalIgnoreCase))
                    fields.Add("Event ID (exact)");
            }
            else if (IPAddress.TryParse(term, out var ip))
            {
                AddExactIp(fields, "Source IP", row.SourceIp, ip);
                AddExactIp(fields, "Destination IP", row.DestinationIp, ip);
            }
            else if (TryParsePortQuery(term, out var port))
            {
                if (row.SourcePort == port) fields.Add("Source port (exact)");
                if (row.DestinationPort == port) fields.Add("Destination port (exact)");
            }
            else
            {
                AddTextMatch(fields, "Source IP", row.SourceIp, term);
                AddTextMatch(fields, "Destination IP", row.DestinationIp, term);
                AddTextMatch(fields, "Rule ID", row.RuleId, term);
                AddTextMatch(fields, "Rule name", row.RuleName, term);
                AddTextMatch(fields, "Description", row.Description, term);
                AddTextMatch(fields, "Country", row.Country, term);
                AddTextMatch(fields, "Destination host", row.DestinationHost, term);
                AddTextMatch(fields, "Process name", row.ProcessName, term);
                AddTextMatch(fields, "Event ID", row.EventId, term);
                AddTextMatch(fields, "Flow ID", row.FlowId, term);
                AddTextMatch(fields, "Correlation ID", row.CorrelationId, term);
                AddTextMatch(fields, "Protocol", row.Protocol, term);
            }
            return fields;
        }

        internal static IReadOnlyList<string> IncidentMatchFields(Incident row, string term)
        {
            var fields = new List<string>();
            if (string.IsNullOrWhiteSpace(term)) return fields;
            term = term.Trim();
            if (term.StartsWith("event:", StringComparison.OrdinalIgnoreCase))
            {
                if (TryParseEventQuery(term, out var id) && IncidentReferencesEvent(row, id))
                    fields.Add("Related event ID (exact reference)");
            }
            else if (IPAddress.TryParse(term, out var ip))
            {
                AddExactIp(fields, "Primary source IP", row.PrimarySourceIp, ip);
                AddExactIp(fields, "Primary destination IP", row.PrimaryDestinationIp, ip);
            }
            else if (!TryParsePortQuery(term, out _))
            {
                if (string.Equals(row.Id, term, StringComparison.OrdinalIgnoreCase)) fields.Add("Case ID (exact)");
                AddTextMatch(fields, "Case title", row.Title, term);
                AddTextMatch(fields, "Case category", row.Category, term);
                AddTextMatch(fields, "Primary destination host", row.PrimaryDestinationHost, term);
            }
            return fields;
        }

        private static void AddExactIp(List<string> fields, string label, string? value, IPAddress searched)
        {
            if (MatchesAddress(value, searched)) fields.Add(label + " (exact)");
        }

        private static void AddTextMatch(List<string> fields, string label, string? value, string term)
        {
            if (Contains(value, term)) fields.Add(label);
        }

        private static IReadOnlyList<KeyValuePair<string, string>> WithMatchContext(
            IReadOnlyList<KeyValuePair<string, string>> evidence, IReadOnlyList<string> matched, string term)
        {
            var context = new List<KeyValuePair<string, string>>
            {
                new("Search · provenance", term.Length == 0 ? "All retained rows · no query applied"
                    : matched.Count == 0 ? "No matching recorded field in the current query"
                    : "Matched recorded fields: " + string.Join(", ", matched))
            };
            context.AddRange(evidence);
            return context;
        }

        private void InvestigationTrafficGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (InvestigationTrafficGrid.SelectedItem is TrafficRecord row)
                SetEvidenceInspector(TrafficEvidenceExpander, TrafficEvidenceFields,
                    "Selected traffic evidence · recorded fields", WithMatchContext(BuildTrafficEvidence(row), TrafficMatchFields(row, _executedSearchTerm), _executedSearchTerm));
            else
                SetEvidenceInspector(TrafficEvidenceExpander, TrafficEvidenceFields,
                    "Selected traffic evidence · choose a row above", null);
            UpdateMatchNavigationControls();
        }

        private void InvestigationDetectionsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (InvestigationDetectionsGrid.SelectedItem is DetectionEvent row)
            {
                SetEvidenceInspector(DetectionEvidenceExpander, DetectionEvidenceFields,
                    "Selected detection evidence · event details", WithMatchContext(BuildDetectionEvidence(row), DetectionMatchFields(row, _executedSearchTerm), _executedSearchTerm));
                ShowExactCaseLinks(row);
            }
            else
            {
                SetEvidenceInspector(DetectionEvidenceExpander, DetectionEvidenceFields,
                    "Selected detection evidence · choose a row above", null);
                ClearCaseLinks();
            }
            UpdateMatchNavigationControls();
        }

        private void InvestigationIncidentsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (InvestigationIncidentsGrid.SelectedItem is Incident row)
            {
                SetEvidenceInspector(IncidentEvidenceExpander, IncidentEvidenceFields,
                    "Selected incident case context · recorded case", WithMatchContext(BuildIncidentEvidence(row), IncidentMatchFields(row, _executedSearchTerm), _executedSearchTerm));
                ShowExactDetectionLinks(row);
            }
            else
            {
                SetEvidenceInspector(IncidentEvidenceExpander, IncidentEvidenceFields,
                    "Selected incident case context · choose a row above", null);
                ClearDetectionLinks();
            }
            UpdateMatchNavigationControls();
        }

        // Return -1 at a boundary; never wrap to a different record silently.
        // When nothing is selected, Next begins at the first retained match
        // and Previous begins at the last retained match.
        internal static int NextMatchIndex(int count, int current, int direction)
        {
            if (count <= 0 || (direction != -1 && direction != 1) || current < -1 || current >= count)
                return -1;
            if (current == -1) return direction == 1 ? 0 : count - 1;
            var next = current + direction;
            return next >= 0 && next < count ? next : -1;
        }

        private static void NavigateMatch(DataGrid grid, int direction)
        {
            var index = NextMatchIndex(grid.Items.Count, grid.SelectedIndex, direction);
            if (index < 0) return;
            var item = grid.Items[index];
            grid.SelectedItem = item;
            grid.ScrollIntoView(item);
            grid.Focus();
        }

        internal static int MatchKeyboardDirection(Key key, ModifierKeys modifiers)
            => modifiers == ModifierKeys.Alt
                ? key == Key.Up ? -1 : key == Key.Down ? 1 : 0
                : 0;

        private void InvestigationMatchGrid_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (sender is not DataGrid grid ||
                (grid != InvestigationTrafficGrid && grid != InvestigationDetectionsGrid && grid != InvestigationIncidentsGrid))
                return;
            // WPF reports Alt-modified keys via SystemKey, not ordinary Key.
            var key = e.Key == Key.System ? e.SystemKey : e.Key;
            var direction = MatchKeyboardDirection(key, Keyboard.Modifiers);
            if (direction == 0) return;
            NavigateMatch(grid, direction);
            e.Handled = true;
        }

        private void PreviousTrafficMatch_Click(object sender, RoutedEventArgs e) => NavigateMatch(InvestigationTrafficGrid, -1);
        private void NextTrafficMatch_Click(object sender, RoutedEventArgs e) => NavigateMatch(InvestigationTrafficGrid, 1);
        private void PreviousDetectionMatch_Click(object sender, RoutedEventArgs e) => NavigateMatch(InvestigationDetectionsGrid, -1);
        private void NextDetectionMatch_Click(object sender, RoutedEventArgs e) => NavigateMatch(InvestigationDetectionsGrid, 1);
        private void PreviousIncidentMatch_Click(object sender, RoutedEventArgs e) => NavigateMatch(InvestigationIncidentsGrid, -1);
        private void NextIncidentMatch_Click(object sender, RoutedEventArgs e) => NavigateMatch(InvestigationIncidentsGrid, 1);

        private void UpdateMatchNavigationControls()
        {
            // SelectionChanged may fire while the XAML visual tree is being
            // initialized, before later named navigation controls are assigned.
            if (PreviousTrafficMatchButton is null || NextTrafficMatchButton is null || TrafficMatchPositionText is null ||
                PreviousDetectionMatchButton is null || NextDetectionMatchButton is null || DetectionMatchPositionText is null ||
                PreviousIncidentMatchButton is null || NextIncidentMatchButton is null || IncidentMatchPositionText is null)
                return;
            UpdateMatchNavigation(InvestigationTrafficGrid, PreviousTrafficMatchButton, NextTrafficMatchButton,
                TrafficMatchPositionText, "record");
            UpdateMatchNavigation(InvestigationDetectionsGrid, PreviousDetectionMatchButton, NextDetectionMatchButton,
                DetectionMatchPositionText, "detection");
            UpdateMatchNavigation(InvestigationIncidentsGrid, PreviousIncidentMatchButton, NextIncidentMatchButton,
                IncidentMatchPositionText, "case");
        }

        private static void UpdateMatchNavigation(DataGrid grid, Button previous, Button next,
            TextBlock status, string label)
        {
            var count = grid.Items.Count;
            var selected = grid.SelectedIndex;
            previous.IsEnabled = NextMatchIndex(count, selected, -1) >= 0;
            next.IsEnabled = NextMatchIndex(count, selected, 1) >= 0;
            status.Text = count == 0 ? $"No matching {label}s"
                : selected < 0 ? $"No {label} selected · {count:N0} retained matches"
                : $"{label} {selected + 1:N0} of {count:N0} retained matches";
        }

        private static bool IncidentReferencesEvent(Incident incident, string? eventId)
        {
            if (string.IsNullOrWhiteSpace(eventId))
                return false;
            return incident.RelatedEventIds?.Any(id =>
                       string.Equals(id, eventId, StringComparison.OrdinalIgnoreCase)) == true
                   || incident.RelatedEvents?.Any(evt => evt is not null &&
                       string.Equals(evt.EventId, eventId, StringComparison.OrdinalIgnoreCase)) == true;
        }

        private void ShowExactCaseLinks(DetectionEvent detection)
        {
            LinkedCasesPanel.Visibility = Visibility.Visible;
            var matches = _cachedIncidentCases
                .Where(incident => !string.IsNullOrWhiteSpace(incident.Id) &&
                                   IncidentReferencesEvent(incident, detection.EventId))
                .GroupBy(incident => incident.Id, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .Take(25)
                .Select(incident => new KeyValuePair<string, Incident>(
                    $"{Limit(incident.Id, 34)} · {Limit(incident.Title, 65)}", incident))
                .ToArray();

            LinkedCasesCombo.ItemsSource = matches;
            LinkedCasesCombo.SelectedIndex = matches.Length == 0 ? -1 : 0;
            LinkedCasesStatusText.Text = string.IsNullOrWhiteSpace(detection.EventId)
                ? "This detection has no recorded event ID; exact case linkage is unavailable."
                : matches.Length == 0
                    ? $"No explicit event-ID reference found in {_cachedIncidentCases.Length:N0} cached cases. This does not rule out journal or older cases."
                    : $"{matches.Length:N0} actual cached case(s) explicitly reference this event ID (up to 25 shown).";
            OpenLinkedCaseButton.IsEnabled = LinkedCasesCombo.SelectedItem is KeyValuePair<string, Incident>;
        }

        private void ShowExactDetectionLinks(Incident incident)
        {
            LinkedDetectionsPanel.Visibility = Visibility.Visible;
            var referencedIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (incident.RelatedEventIds is not null)
                foreach (var id in incident.RelatedEventIds.Where(id => !string.IsNullOrWhiteSpace(id)))
                    referencedIds.Add(id);
            if (incident.RelatedEvents is not null)
                foreach (var evt in incident.RelatedEvents.Where(evt => evt is not null && !string.IsNullOrWhiteSpace(evt.EventId)))
                    referencedIds.Add(evt.EventId);

            var matches = _cachedDetectionEvents
                .Where(evt => !string.IsNullOrWhiteSpace(evt.EventId) && referencedIds.Contains(evt.EventId))
                .GroupBy(evt => evt.EventId, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .Take(25)
                .Select(evt => new KeyValuePair<string, DetectionEvent>(
                    $"{Limit(evt.EventId, 42)} · {Limit(evt.RuleId, 22)}", evt))
                .ToArray();

            LinkedDetectionsCombo.ItemsSource = matches;
            LinkedDetectionsCombo.SelectedIndex = matches.Length == 0 ? -1 : 0;
            LinkedDetectionsStatusText.Text = referencedIds.Count == 0
                ? "This cached case lists no related event IDs. No detection link is inferred from its IP addresses."
                : matches.Length == 0
                    ? $"Case references {referencedIds.Count:N0} event ID(s), but none are in the retained {_cachedDetectionEvents.Length:N0}-row detection snapshot."
                    : $"{matches.Length:N0} explicitly related detection(s) are in the retained snapshot (up to 25 shown).";
            InspectLinkedDetectionButton.IsEnabled = LinkedDetectionsCombo.SelectedItem is KeyValuePair<string, DetectionEvent>;
        }

        private void ClearExactLinks()
        {
            ClearCaseLinks();
            ClearDetectionLinks();
        }

        private void ClearCaseLinks()
        {
            LinkedCasesCombo.ItemsSource = null;
            LinkedCasesPanel.Visibility = Visibility.Collapsed;
            OpenLinkedCaseButton.IsEnabled = false;
        }

        private void ClearDetectionLinks()
        {
            LinkedDetectionsCombo.ItemsSource = null;
            LinkedDetectionsPanel.Visibility = Visibility.Collapsed;
            InspectLinkedDetectionButton.IsEnabled = false;
        }

        private void LinkedCasesCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
            => OpenLinkedCaseButton.IsEnabled = LinkedCasesCombo.SelectedItem is KeyValuePair<string, Incident>;

        private void LinkedDetectionsCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
            => InspectLinkedDetectionButton.IsEnabled = LinkedDetectionsCombo.SelectedItem is KeyValuePair<string, DetectionEvent>;

        private void OpenLinkedCase_Click(object sender, RoutedEventArgs e)
        {
            if (LinkedCasesCombo.SelectedItem is KeyValuePair<string, Incident> link &&
                !string.IsNullOrWhiteSpace(link.Value.Id))
                IncidentRequested?.Invoke(link.Value.Id);
        }

        private void InspectLinkedDetection_Click(object sender, RoutedEventArgs e)
        {
            if (LinkedDetectionsCombo.SelectedItem is not KeyValuePair<string, DetectionEvent> link ||
                string.IsNullOrWhiteSpace(link.Value.EventId) || link.Value.EventId.Length > 128)
                return;

            InvestigationSearchText.Text = "event:" + link.Value.EventId;
            SearchRequested?.Invoke(this, new RoutedEventArgs());
        }

        private static void SetEvidenceInspector(Expander panel, ItemsControl fields, string title,
            IReadOnlyList<KeyValuePair<string, string>>? details)
        {
            panel.Header = title;
            fields.ItemsSource = details;
            panel.IsExpanded = details is { Count: > 0 };
        }

        private static IReadOnlyList<KeyValuePair<string, string>> BuildTrafficEvidence(TrafficRecord row)
        {
            var fields = new List<KeyValuePair<string, string>>();
            Add(fields, "Record · local ID", row.Id.ToString("N"));
            Add(fields, "Record · observed at", row.Timestamp);
            Add(fields, "Endpoints · source", row.Source);
            Add(fields, "Endpoints · source scope", DescribeScope(row.Source));
            Add(fields, "Endpoints · source port", row.SourcePort?.ToString());
            Add(fields, "Endpoints · destination", row.Destination);
            Add(fields, "Endpoints · destination scope", DescribeScope(row.Destination));
            Add(fields, "Endpoints · destination port", row.DestinationPort?.ToString());
            Add(fields, "Endpoints · source MAC", row.MacSource);
            Add(fields, "Endpoints · destination MAC", row.MacDestination);
            Add(fields, "Packet · network protocol", row.Protocol);
            Add(fields, "Packet · IP version", row.IpVersion?.ToString());
            Add(fields, "Packet · captured length", row.Length > 0 ? $"{row.Length:N0} bytes" : null);
            Add(fields, "Packet · transport length", row.L4Len?.ToString());
            Add(fields, "Packet · flags", row.Flags);
            Add(fields, "Packet · TTL", row.TTL);
            Add(fields, "Application · protocol", row.ApplicationProtocol);
            Add(fields, "Application · service", row.ApplicationService);
            Add(fields, "Application · HTTP method", row.HttpMethod);
            Add(fields, "Application · HTTP host", row.HttpHost);
            Add(fields, "Application · DNS query", row.DnsQname);
            Add(fields, "Application · DNS type", row.DnsQtype);
            Add(fields, "Application · DNS result", row.DnsRcode);
            Add(fields, "Application · TLS SNI", row.Sni);
            Add(fields, "Application · TLS version", row.TlsVersion);
            Add(fields, "Application · JA3", row.Ja3);
            Add(fields, "Application · JA4", row.Ja4);
            Add(fields, "Application · JA4S", row.Ja4S);
            Add(fields, "Application · QUIC version", row.QuicVersion);
            Add(fields, "Host · process name", row.ProcessName);
            Add(fields, "Host · process ID", row.ProcessId > 0 ? row.ProcessId.ToString() : null);
            Add(fields, "Host · network type", row.NetworkType);
            Add(fields, "Host · VPN classified", FormatOptionalBoolean(row.IsVpn));
            Add(fields, "Host · proxy classified", FormatOptionalBoolean(row.IsProxy));
            Add(fields, "Enrichment · source country", row.SrcCountry);
            Add(fields, "Enrichment · destination country", row.DstCountry);
            Add(fields, "Enrichment · WHOIS country (endpoint unspecified)", row.WhoisCountry);
            Add(fields, "Enrichment · WHOIS organization", row.WhoisOrganization);
            Add(fields, "Enrichment · WHOIS ASN", row.WhoisASN);
            return fields;
        }

        private static IReadOnlyList<KeyValuePair<string, string>> BuildDetectionEvidence(DetectionEvent row)
        {
            var fields = new List<KeyValuePair<string, string>>();
            Add(fields, "Event · ID", row.EventId);
            Add(fields, "Event · timestamp (UTC when known)", FormatUtc(row.TimestampUtc));
            Add(fields, "Rule · ID", row.RuleId);
            Add(fields, "Rule · name", row.RuleName);
            Add(fields, "Rule · severity", row.Severity.ToString());
            Add(fields, "Rule · description", row.Description);
            Add(fields, "Rule · maturity at event", row.RuleMaturityAtDetection);
            Add(fields, "Rule · revision at event", row.RuleRevisionAtDetection > 0 ? row.RuleRevisionAtDetection.ToString() : null);
            Add(fields, "Evidence · confidence label", row.ConfidenceLabel.ToString());
            Add(fields, "Evidence · confidence score",
                row.ConfidenceLabel == DetectionConfidenceLabel.Unknown && row.ConfidenceScore == 0
                    ? null : row.ConfidenceScore.ToString("0.###"));
            Add(fields, "Event · occurrence count", row.Count > 0 ? row.Count.ToString() : null);
            Add(fields, "Event · evaluation window", row.WindowSeconds > 0 ? $"{row.WindowSeconds} seconds" : null);
            Add(fields, "Endpoints · source", row.SourceIp);
            Add(fields, "Endpoints · source scope", DescribeScope(row.SourceIp));
            Add(fields, "Endpoints · source port", row.SourcePort?.ToString());
            Add(fields, "Endpoints · destination", row.DestinationIp);
            Add(fields, "Endpoints · destination scope", DescribeScope(row.DestinationIp));
            Add(fields, "Endpoints · destination port", row.DestinationPort?.ToString());
            Add(fields, "Endpoints · destination host", row.DestinationHost);
            Add(fields, "Event · protocol", row.Protocol);
            Add(fields, "Host · process name", row.ProcessName);
            Add(fields, "Enrichment · country (endpoint unspecified)", row.Country);
            Add(fields, "Enrichment · ASN", row.Asn);
            Add(fields, "Fingerprint · JA4", row.Ja4);
            Add(fields, "Fingerprint · HASSH", row.Hassh);
            Add(fields, "Correlation · packet ID", row.PacketId);
            Add(fields, "Correlation · flow ID", row.FlowId);
            Add(fields, "Correlation · correlation ID", row.CorrelationId);
            Add(fields, "Delivery · local journal", row.DeliveryStatus.ToString());
            Add(fields, "Delivery · persisted UTC", row.PersistedAtUtc.HasValue ? FormatUtc(row.PersistedAtUtc.Value) : null);
            Add(fields, "Delivery · external sink", row.ExternalDeliveryStatus.ToString());
            Add(fields, "Sensor · ID", row.SensorId);
            Add(fields, "Sensor · site", row.SiteId);
            Add(fields, "Sensor · capture interface", row.CaptureInterface);

            var evidence = row.StructuredEvidence?.Items;
            if (evidence is null)
            {
                Add(fields, "Structured evidence · approved metadata", null);
            }
            else
            {
                // IsSensitive defaults to false, including for arbitrary legacy
                // Evidence strings. Only explicitly approved typed metadata may
                // have its value shown here; the raw legacy field stays hidden.
                var approved = evidence.Select(item =>
                    (Item: item, Value: TryGetApprovedEvidenceValue(item)))
                    .Where(entry => entry.Value is not null)
                    .Take(12).ToArray();
                Add(fields, "Structured evidence · approved metadata",
                    $"Showing {approved.Length} approved typed entries of {evidence.Count} total (maximum 12 shown; all other values withheld)");
                foreach (var entry in approved)
                    Add(fields, $"Evidence · {entry.Item.Key.Trim().ToLowerInvariant()}", entry.Value);
            }

            return fields;
        }

        private static IReadOnlyList<KeyValuePair<string, string>> BuildIncidentEvidence(Incident row)
        {
            var fields = new List<KeyValuePair<string, string>>();
            Add(fields, "Case · ID", row.Id);
            Add(fields, "Case · title", row.Title);
            Add(fields, "Case · category", row.Category);
            Add(fields, "Case · severity", row.Severity);
            Add(fields, "Case · status", row.Status);
            Add(fields, "Case · risk score", row.RiskScore.ToString());
            Add(fields, "Case · primary rule", row.PrimaryRuleId);
            Add(fields, "Case · related rule IDs", row.RelatedRuleIds?.Count.ToString());
            Add(fields, "Case · related event IDs", row.RelatedEventIds?.Count.ToString());
            Add(fields, "Case · timeline entries", row.TimelineItems?.Count.ToString());
            Add(fields, "Case · occurrence count", row.OccurrenceCount > 0 ? row.OccurrenceCount.ToString() : null);
            Add(fields, "Case · first observed UTC", FormatUtc(row.FirstSeenUtc));
            Add(fields, "Case · last observed UTC", FormatUtc(row.LastSeenUtc));
            Add(fields, "Case · created UTC", FormatUtc(row.CreatedUtc));
            Add(fields, "Case · updated UTC", FormatUtc(row.UpdatedUtc));
            Add(fields, "Endpoints · source", row.PrimarySourceIp);
            Add(fields, "Endpoints · source scope", DescribeScope(row.PrimarySourceIp));
            Add(fields, "Endpoints · destination", row.PrimaryDestinationIp);
            Add(fields, "Endpoints · destination scope", DescribeScope(row.PrimaryDestinationIp));
            Add(fields, "Endpoints · destination host", row.PrimaryDestinationHost);
            Add(fields, "Correlation · reason", row.CorrelationReason);
            return fields;
        }

        private static string DescribeScope(string? address)
        {
            if (!IPAddress.TryParse(address, out var ip))
                return string.IsNullOrWhiteSpace(address) ? "Not recorded" : "Unclassified (not an IP address)";

            // This is an analyst display hint, not a sensor-network inventory
            // or a claim that an address is reachable via the public Internet.
            // Map IPv4-mapped IPv6 before matching private IPv4 ranges.
            var normalized = ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : ip.ToString();
            var result = LocalAddressDefaults.ClassifyAddress(normalized);
            return result.Zone switch
            {
                NetworkBoundaryZone.Internal => "Local/private · default private address range",
                NetworkBoundaryZone.Loopback => "Local · loopback",
                NetworkBoundaryZone.LinkLocal => "Local · link-local",
                NetworkBoundaryZone.External => "Outside default local ranges · public reachability unverified",
                NetworkBoundaryZone.Unknown => "Unclassified",
                _ => $"{result.Zone} · boundary profile"
            };
        }

        private static string? FormatOptionalBoolean(bool? value)
            => value.HasValue ? value.Value ? "Yes" : "No" : null;

        private static string? TryGetApprovedEvidenceValue(DetectionEvidenceItem? item)
        {
            if (item is null || item.IsSensitive || string.IsNullOrWhiteSpace(item.Key)
                || string.IsNullOrWhiteSpace(item.Value)
                || string.Equals(item.Source, "legacy-evidence", StringComparison.OrdinalIgnoreCase))
                return null;

            // These keys have verifiable scalar shapes. A generic "rule" or
            // "traffic-record" source alone is NOT a safe display contract.
            switch (item.Key.Trim().ToLowerInvariant())
            {
                case "count":
                case "window_seconds":
                case "flow.bytes":
                case "network.destinationport":
                case "dns.ttl":
                case "reputation.score":
                    return long.TryParse(item.Value, NumberStyles.None,
                        CultureInfo.InvariantCulture, out var number) && number >= 0
                        ? number.ToString(CultureInfo.InvariantCulture) : null;
                case "telemetry.coverage_ratio":
                    return double.TryParse(item.Value, NumberStyles.AllowDecimalPoint,
                        CultureInfo.InvariantCulture, out var ratio) && ratio is >= 0 and <= 1
                        ? ratio.ToString("0.###", CultureInfo.InvariantCulture) : null;
                case "http.method":
                    return item.Value.Trim().ToUpperInvariant() switch
                    {
                        "GET" or "POST" or "HEAD" or "PUT" or "PATCH" or "DELETE" or "OPTIONS" =>
                            item.Value.Trim().ToUpperInvariant(),
                        _ => null
                    };
                default:
                    return null;
            }
        }

        private static string? FormatUtc(DateTime value)
        {
            if (value == default)
                return null;
            if (value.Kind == DateTimeKind.Unspecified)
                return value.ToString("yyyy-MM-dd HH:mm:ss") + " (timezone unspecified)";
            return value.ToUniversalTime().ToString("u");
        }

        private static string Limit(string? value, int maxLength)
        {
            if (string.IsNullOrWhiteSpace(value))
                return "Not recorded";
            var trimmed = value.Trim();
            return trimmed.Length > maxLength ? trimmed[..maxLength] + "…" : trimmed;
        }

        private static void Add(ICollection<KeyValuePair<string, string>> fields, string key, string? value)
            => fields.Add(new KeyValuePair<string, string>(key, Limit(value, 400)));

        private void Investigate_Click(object sender, RoutedEventArgs e)
            => SearchRequested?.Invoke(this, e);

        private void Refresh_Click(object sender, RoutedEventArgs e)
            => SearchRequested?.Invoke(this, e);

        private void InvestigationSearchText_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key != Key.Enter)
                return;
            SearchRequested?.Invoke(this, new RoutedEventArgs());
            e.Handled = true;
        }

        private void OpenTraffic_Click(object sender, RoutedEventArgs e)
            => TrafficRequested?.Invoke(this, e);

        private void OpenDetections_Click(object sender, RoutedEventArgs e)
            => DetectionsRequested?.Invoke(this, e);

        private void OpenAnalytics_Click(object sender, RoutedEventArgs e)
            => AnalyticsRequested?.Invoke(this, e);

        private void OpenIncidentQueue_Click(object sender, RoutedEventArgs e)
            => IncidentQueueRequested?.Invoke(this, e);

        private void OpenDetectionRules_Click(object sender, RoutedEventArgs e)
            => DetectionRulesRequested?.Invoke(this, e);

        private void OpenSelectedIncident_Click(object sender, RoutedEventArgs e)
        {
            if (InvestigationIncidentsGrid.SelectedItem is Incident incident && !string.IsNullOrWhiteSpace(incident.Id))
                IncidentRequested?.Invoke(incident.Id);
        }
    }
}
