// SPDX-License-Identifier: MIT
// File: Views/DashboardSignalDetailDialog.xaml.cs
using System;
using System.Collections.Generic;
using System.Text;
using System.Windows;
using System.Windows.Media;

namespace Carthago.Views
{
    public partial class DashboardSignalDetailDialog : Window
    {
        public DashboardSignalDetailDialog(DashboardSignalDetailDialogModel model)
        {
            InitializeComponent();
            DataContext = model;
            SourceInitialized += (_, _) => ConstrainToOwner();
            Loaded += (_, _) => ConstrainToOwner();
            SizeChanged += (_, _) => MetadataGrid.Columns = ActualWidth < 800 ? 2 : 3;
        }

        private void ConstrainToOwner()
        {
            const double preferredMinWidth = 520;
            const double preferredMinHeight = 400;
            var workArea = SystemParameters.WorkArea;
            var ownerWidth = Owner?.ActualWidth > 0 ? Owner.ActualWidth : workArea.Width;
            var ownerHeight = Owner?.ActualHeight > 0 ? Owner.ActualHeight : workArea.Height;
            var availableWidth = Math.Min(ownerWidth, workArea.Width);
            var availableHeight = Math.Min(ownerHeight, workArea.Height);
            var maximumWidth = availableWidth * 0.94;
            var maximumHeight = availableHeight * 0.94;

            MinWidth = Math.Min(preferredMinWidth, maximumWidth);
            MinHeight = Math.Min(preferredMinHeight, maximumHeight);
            MaxWidth = maximumWidth;
            MaxHeight = maximumHeight;
            Width = ResponsiveLayout.ConstrainDimension(Width, preferredMinWidth, availableWidth, 0.94);
            Height = ResponsiveLayout.ConstrainDimension(Height, preferredMinHeight, availableHeight, 0.94);
            MetadataGrid.Columns = Width < 800 ? 2 : 3;
        }

        public DashboardSignalDetailDialogAction RequestedAction { get; private set; }

        private DashboardSignalDetailDialogModel Model
            => (DashboardSignalDetailDialogModel)DataContext;

        private void CopySummary_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(Model.BuildClipboardSummary());
        }

        private void OpenAnomalies_Click(object sender, RoutedEventArgs e)
        {
            RequestedAction = DashboardSignalDetailDialogAction.OpenAnomalies;
            DialogResult = true;
        }

        private void OpenIncident_Click(object sender, RoutedEventArgs e)
        {
            RequestedAction = DashboardSignalDetailDialogAction.OpenIncident;
            DialogResult = true;
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }

    public enum DashboardSignalDetailDialogAction
    {
        None,
        OpenIncident,
        OpenAnomalies
    }

    public sealed class DashboardSignalDetailDialogModel
    {
        public string Title { get; init; } = "No selected signal";
        public string Subtitle { get; init; } = "Start monitoring or run demo mode to populate the workspace.";
        public string Source { get; init; } = "—";
        public string Destination { get; init; } = "—";
        public string Protocol { get; init; } = "—";
        public string Category { get; init; } = "—";
        public string Detected { get; init; } = "—";
        public string RelatedIncident { get; init; } = "Not correlated yet";
        public string RiskText { get; init; } = "—";
        public string RiskLabel { get; init; } = "Learning";
        public Brush RiskBrush { get; init; } = Brushes.LightSlateGray;
        public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();
        public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();
        public IReadOnlyList<string> Rules { get; init; } = Array.Empty<string>();
        public IReadOnlyList<string> RecommendedActions { get; init; } = Array.Empty<string>();
        public string? IncidentId { get; init; }
        public string? AnomalyId { get; init; }

        public bool CanOpenIncident => !string.IsNullOrWhiteSpace(IncidentId);
        public bool CanOpenAnomalies => !string.IsNullOrWhiteSpace(AnomalyId);

        public string BuildClipboardSummary()
        {
            var buffer = new StringBuilder();
            buffer.AppendLine(Title);
            buffer.AppendLine(Subtitle);
            buffer.AppendLine();
            buffer.AppendLine($"Risk: {RiskText} ({RiskLabel})");
            buffer.AppendLine($"Source: {Source}");
            buffer.AppendLine($"Destination: {Destination}");
            buffer.AppendLine($"Protocol / port: {Protocol}");
            buffer.AppendLine($"Category: {Category}");
            buffer.AppendLine($"Detected: {Detected}");
            buffer.AppendLine($"Related incident: {RelatedIncident}");
            buffer.AppendLine();
            buffer.AppendLine("Reasons:");
            AppendLines(buffer, Reasons);
            buffer.AppendLine();
            buffer.AppendLine("Tags:");
            AppendLines(buffer, Tags);
            buffer.AppendLine();
            buffer.AppendLine("Related rule IDs:");
            AppendLines(buffer, Rules);
            buffer.AppendLine();
            buffer.AppendLine("Recommended actions:");
            AppendLines(buffer, RecommendedActions);
            return buffer.ToString().Trim();
        }

        private static void AppendLines(StringBuilder buffer, IReadOnlyList<string> values)
        {
            if (values.Count == 0)
            {
                buffer.AppendLine("- None");
                return;
            }

            foreach (var value in values)
                buffer.AppendLine($"- {value}");
        }
    }
}
