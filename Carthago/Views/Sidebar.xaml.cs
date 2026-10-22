// SPDX-License-Identifier: MIT
// File: Views/Sidebar.xaml.cs
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Carthago.Views
{
    public partial class Sidebar : UserControl
    {
        public static readonly DependencyProperty IsCompactProperty = DependencyProperty.Register(
            nameof(IsCompact),
            typeof(bool),
            typeof(Sidebar),
            new PropertyMetadata(false, OnIsCompactChanged));

        public bool IsCompact
        {
            get => (bool)GetValue(IsCompactProperty);
            set => SetValue(IsCompactProperty, value);
        }

        public Sidebar()
        {
            InitializeComponent();
            Loaded += (_, __) => SetActiveNavButton(DashboardNavButton);
        }

        private static void OnIsCompactChanged(DependencyObject sender, DependencyPropertyChangedEventArgs e)
        {
            if (sender is Sidebar sidebar)
                sidebar.UpdateCompactPresentation((bool)e.NewValue);
        }

        private void UpdateCompactPresentation(bool compact)
        {
            Width = double.NaN;
            BrandText.Visibility = compact ? Visibility.Collapsed : Visibility.Visible;
            ProductFooter.Visibility = compact ? Visibility.Collapsed : Visibility.Visible;
            BrandHeader.Padding = compact ? new Thickness(12, 18, 12, 16) : new Thickness(18, 18, 16, 16);
            NavigationStack.Margin = compact ? new Thickness(2, 12, 2, 16) : new Thickness(10, 12, 10, 16);

            if (compact)
                HideAllFilters();
        }

        // ======= Navigation events MainWindow subscribes to =======
        public event RoutedEventHandler? DashboardRequested;
        public event RoutedEventHandler? AnomaliesRequested;
        public event RoutedEventHandler? LiveTrafficRequested;
        public event RoutedEventHandler? AlertsRequested;
        public event RoutedEventHandler? IncidentsRequested;
        public event RoutedEventHandler? IncidentQueueRequested;
        public event RoutedEventHandler? ThreatFeedRequested;
        public event RoutedEventHandler? AnalyticsRequested;
        public event RoutedEventHandler? SettingsRequested;
        public event RoutedEventHandler? IntegrationsRequested;
        public event RoutedEventHandler? HostIntegrityRequested;   // Host Integrity view
        public event RoutedEventHandler? SinkEventsRequested;
        public event RoutedEventHandler? CiscoToolsRequested;      // NEW: Cisco Tools view

        // ======= Filter events (Live traffic / Alerts / Sink Events) =======
        public event RoutedEventHandler? TrafficFilterApplyRequested;
        public event RoutedEventHandler? TrafficFilterClearRequested;
        public event RoutedEventHandler? AlertsFilterApplyRequested;
        public event RoutedEventHandler? AlertsFilterClearRequested;
        public event RoutedEventHandler? SinkEventsFilterApplyRequested;
        public event RoutedEventHandler? SinkEventsFilterClearRequested;


        private readonly Brush _transparentBrush = Brushes.Transparent;

        private void SetActiveNavButton(Button? active)
        {
            var buttons = new[]
            {
                DashboardNavButton, IncidentsNavButton, AnomaliesNavButton, IncidentQueueNavButton, ThreatFeedNavButton,
                RawTrafficNavButton, RawDetectionsNavButton, SinkDeliveryNavButton, PcapExplorerNavButton, ForensicsNavButton,
                AnalyticsNavButton, IntegrationsNavButton, HostIntegrityNavButton, CiscoToolsNavButton,
                CaptureSourcesNavButton, DetectionRulesNavButton, ReputationNavButton, UsersRolesNavButton, SystemSettingsNavButton
            };

            foreach (var button in buttons)
            {
                if (button == null)
                    continue;
                var isActive = ReferenceEquals(button, active);
                button.Tag = isActive ? "Active" : null;
                button.Background = isActive
                    ? (Brush)(TryFindResource("SelectionBgBrush") ?? new SolidColorBrush(Color.FromRgb(11, 49, 82)))
                    : _transparentBrush;
            }
        }

        internal void ActivateNav(string navKey)
        {
            var active = navKey switch
            {
                "Dashboard" => DashboardNavButton,
                "Anomalies" => AnomaliesNavButton,
                "LiveTraffic" => RawTrafficNavButton,
                "Alerts" => RawDetectionsNavButton,
                "Incidents" => IncidentsNavButton,
                "IncidentQueue" => IncidentQueueNavButton,
                "ThreatFeed" => ThreatFeedNavButton,
                "Analytics" => AnalyticsNavButton,
                "Integrations" => IntegrationsNavButton,
                "HostIntegrity" => HostIntegrityNavButton,
                "SinkEvents" => SinkDeliveryNavButton,
                "CiscoTools" => CiscoToolsNavButton,
                "CaptureSources" => CaptureSourcesNavButton,
                "DetectionRules" => DetectionRulesNavButton,
                "Reputation" => ReputationNavButton,
                "UsersRoles" => UsersRolesNavButton,
                "SystemSettings" => SystemSettingsNavButton,
                _ => null
            };

            SetActiveNavButton(active);
        }

        // ===================== NAV BUTTON HANDLERS =====================

        private void Nav_Dashboard_Click(object s, RoutedEventArgs e)
        {
            SetActiveNavButton(s as Button);
            DashboardRequested?.Invoke(s, e);
            HideAllFilters();
        }

        private void Nav_Anomalies_Click(object s, RoutedEventArgs e)
        {
            SetActiveNavButton(s as Button);
            AnomaliesRequested?.Invoke(s, e);
            HideAllFilters();
        }

        private void Nav_LiveTraffic_Click(object s, RoutedEventArgs e)
        {
            SetActiveNavButton(s as Button);
            LiveTrafficRequested?.Invoke(s, e);
            ShowOnly(TrafficFilterExpander);
        }

        private void Nav_Alerts_Click(object s, RoutedEventArgs e)
        {
            SetActiveNavButton(s as Button);
            AlertsRequested?.Invoke(s, e);
            ShowOnly(IdsFilterExpander);
        }

        private void Nav_Incidents_Click(object s, RoutedEventArgs e)
        {
            SetActiveNavButton(s as Button);
            IncidentsRequested?.Invoke(s, e);
            HideAllFilters();
        }

        private void Nav_IncidentQueue_Click(object s, RoutedEventArgs e)
        {
            SetActiveNavButton(s as Button);
            IncidentQueueRequested?.Invoke(s, e);
            HideAllFilters();
        }

        private void Nav_ThreatFeed_Click(object s, RoutedEventArgs e)
        {
            SetActiveNavButton(s as Button);
            ThreatFeedRequested?.Invoke(s, e);
            HideAllFilters();
        }

        private void Nav_Analytics_Click(object s, RoutedEventArgs e)
        {
            SetActiveNavButton(s as Button);
            AnalyticsRequested?.Invoke(s, e);
            HideAllFilters();
        }

        private void Nav_Settings_Click(object s, RoutedEventArgs e)
        {
            SetActiveNavButton(s as Button);
            SettingsRequested?.Invoke(s, e);
            HideAllFilters();
        }

        private void Nav_Integrations_Click(object s, RoutedEventArgs e)
        {
            SetActiveNavButton(s as Button);
            IntegrationsRequested?.Invoke(s, e);
            HideAllFilters();
        }

        private void Nav_HostIntegrity_Click(object s, RoutedEventArgs e)
        {
            SetActiveNavButton(s as Button);
            HostIntegrityRequested?.Invoke(s, e);
            HideAllFilters();
        }

        private void Nav_SinkEvents_Click(object s, RoutedEventArgs e)
        {
            SetActiveNavButton(s as Button);
            SinkEventsRequested?.Invoke(s, e);
            ShowOnly(SinkEventsFilterExpander);
        }

        // NEW: Cisco Tools navigation
        private void Nav_CiscoTools_Click(object s, RoutedEventArgs e)
        {
            SetActiveNavButton(s as Button);
            CiscoToolsRequested?.Invoke(s, e);
            HideAllFilters();
        }

        // ===================== FILTER BUTTON HANDLERS =====================

        private void TF_Apply_Click(object s, RoutedEventArgs e)
            => TrafficFilterApplyRequested?.Invoke(s, e);

        private void TF_Clear_Click(object s, RoutedEventArgs e)
            => TrafficFilterClearRequested?.Invoke(s, e);

        private void AF_Apply_Click(object s, RoutedEventArgs e)
            => AlertsFilterApplyRequested?.Invoke(s, e);

        private void AF_Clear_Click(object s, RoutedEventArgs e)
            => AlertsFilterClearRequested?.Invoke(s, e);

        private void SE_Apply_Click(object s, RoutedEventArgs e)
            => SinkEventsFilterApplyRequested?.Invoke(s, e);

        private void SE_Clear_Click(object s, RoutedEventArgs e)
            => SinkEventsFilterClearRequested?.Invoke(s, e);

        // ===================== HELPERS =====================

        /// <summary>
        /// Collapse all filter expanders, then show only the one passed in (if not null).
        /// </summary>
        private void ShowOnly(FrameworkElement? toShow)
        {
            if (TrafficFilterExpander != null)
                TrafficFilterExpander.Visibility = Visibility.Collapsed;

            if (IdsFilterExpander != null)
                IdsFilterExpander.Visibility = Visibility.Collapsed;

            if (SinkEventsFilterExpander != null)
                SinkEventsFilterExpander.Visibility = Visibility.Collapsed;

            if (toShow != null)
            {
                toShow.IsEnabled = true;
                if (toShow is Expander expander)
                    expander.IsExpanded = true;
                toShow.Visibility = Visibility.Visible;
            }

            Width = IsCompact && toShow != null ? 320 : double.NaN;
        }

        /// <summary>
        /// Collapse all filter expanders.
        /// </summary>
        internal void HideAllFilters()
        {
            if (TrafficFilterExpander != null)
                TrafficFilterExpander.Visibility = Visibility.Collapsed;

            if (IdsFilterExpander != null)
                IdsFilterExpander.Visibility = Visibility.Collapsed;

            if (SinkEventsFilterExpander != null)
                SinkEventsFilterExpander.Visibility = Visibility.Collapsed;

            if (IsCompact)
                Width = double.NaN;
        }

        internal void ShowTrafficFilters() => ShowOnly(TrafficFilterExpander);

        internal void ShowDetectionFilters() => ShowOnly(IdsFilterExpander);

        internal void ShowSinkDeliveryFilters() => ShowOnly(SinkEventsFilterExpander);

        private void CompactFilterExpander_Collapsed(object sender, RoutedEventArgs e)
        {
            if (IsCompact)
                HideAllFilters();
        }
    }
}
