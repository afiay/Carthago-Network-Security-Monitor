// SPDX-License-Identifier: MIT
// File: Views/CiscoAnalyzerFlyout.xaml.cs

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using Carthago.Models;

namespace Carthago.Views
{
    public partial class CiscoAnalyzerFlyout : Window
    {
        public IReadOnlyList<DeviceErrorSummary> TopErrorDevices { get; }
        public IReadOnlyList<CategorySummary> TopCategories { get; }
        public PointCollection TimelinePoints { get; }
        public int TotalEvents { get; }
        public int ErrorEvents { get; }
        public int CriticalEvents { get; }

        public CiscoAnalyzerFlyout(IEnumerable<CiscoDevice> devices,
                                   IEnumerable<CiscoSyslogEvent> events)
        {
            InitializeComponent();

            var eventsList = events?.ToList() ?? new List<CiscoSyslogEvent>();

            TotalEvents = eventsList.Count;
            ErrorEvents = eventsList.Count(e =>
                string.Equals(e.SeverityName, "Error", StringComparison.OrdinalIgnoreCase));
            CriticalEvents = eventsList.Count(e =>
                string.Equals(e.SeverityName, "Critical", StringComparison.OrdinalIgnoreCase));

            TopErrorDevices = ComputeTopDevices(eventsList);
            TopCategories = ComputeTopCategories(eventsList);
            TimelinePoints = ComputeTimelinePoints(eventsList);

            DataContext = this;
        }

        private static IReadOnlyList<DeviceErrorSummary> ComputeTopDevices(
            IReadOnlyList<CiscoSyslogEvent> events)
        {
            var byDevice = events
                .GroupBy(e => string.IsNullOrWhiteSpace(e.DeviceName)
                    ? (string.IsNullOrWhiteSpace(e.DeviceOrHost) ? e.Host ?? "Unknown" : e.DeviceOrHost)
                    : e.DeviceName)
                .Select(g =>
                {
                    int crit = g.Count(ev =>
                        string.Equals(ev.SeverityName, "Critical", StringComparison.OrdinalIgnoreCase));
                    int err = g.Count(ev =>
                        string.Equals(ev.SeverityName, "Error", StringComparison.OrdinalIgnoreCase));
                    int warn = g.Count(ev =>
                        string.Equals(ev.SeverityName, "Warning", StringComparison.OrdinalIgnoreCase));
                    int total = g.Count();

                    return new DeviceErrorSummary
                    {
                        DeviceLabel = g.Key,
                        CriticalCount = crit,
                        ErrorCount = err,
                        WarningCount = warn,
                        TotalCount = total
                    };
                })
                .OrderByDescending(d => d.CriticalCount * 100 + d.ErrorCount * 10 + d.WarningCount)
                .Take(10)
                .ToList();

            return byDevice;
        }

        private static IReadOnlyList<CategorySummary> ComputeTopCategories(
            IReadOnlyList<CiscoSyslogEvent> events)
        {
            var byCat = events
                .GroupBy(e => string.IsNullOrWhiteSpace(e.Category) ? "Uncategorised" : e.Category)
                .Select(g =>
                {
                    int crit = g.Count(ev =>
                        string.Equals(ev.SeverityName, "Critical", StringComparison.OrdinalIgnoreCase));
                    int err = g.Count(ev =>
                        string.Equals(ev.SeverityName, "Error", StringComparison.OrdinalIgnoreCase));
                    int warn = g.Count(ev =>
                        string.Equals(ev.SeverityName, "Warning", StringComparison.OrdinalIgnoreCase));
                    int total = g.Count();

                    return new CategorySummary
                    {
                        Category = g.Key,
                        CriticalCount = crit,
                        ErrorCount = err,
                        WarningCount = warn,
                        TotalCount = total
                    };
                })
                .OrderByDescending(c => c.CriticalCount * 100 + c.ErrorCount * 10 + c.WarningCount)
                .Take(15)
                .ToList();

            return byCat;
        }

        private static PointCollection ComputeTimelinePoints(IReadOnlyList<CiscoSyslogEvent> events)
        {
            var points = new PointCollection();
            if (events.Count == 0)
                return points;

            // 60-minute window
            var now = DateTime.UtcNow;
            var from = now.AddMinutes(-60);

            var buckets = new int[60];

            foreach (var ev in events)
            {
                var ts = ev.Timestamp;
                if (ts < from || ts > now)
                    continue;

                var minutes = (int)Math.Floor((ts - from).TotalMinutes);
                if (minutes < 0) minutes = 0;
                if (minutes > 59) minutes = 59;

                // Weight severe events more heavily
                int weight = 1;
                if (string.Equals(ev.SeverityName, "Error", StringComparison.OrdinalIgnoreCase))
                    weight = 3;
                else if (string.Equals(ev.SeverityName, "Critical", StringComparison.OrdinalIgnoreCase))
                    weight = 5;

                buckets[minutes] += weight;
            }

            int max = buckets.Max();
            if (max <= 0)
                max = 1;

            const double width = 260.0;
            const double height = 60.0;

            for (int i = 0; i < buckets.Length; i++)
            {
                double x = (width * i) / (buckets.Length - 1);
                double y = height - (buckets[i] / (double)max) * height;
                points.Add(new Point(x, y));
            }

            return points;
        }
    }

    public sealed class DeviceErrorSummary
    {
        public string DeviceLabel { get; set; } = string.Empty;
        public int CriticalCount { get; set; }
        public int ErrorCount { get; set; }
        public int WarningCount { get; set; }
        public int TotalCount { get; set; }
    }

    public sealed class CategorySummary
    {
        public string Category { get; set; } = string.Empty;
        public int CriticalCount { get; set; }
        public int ErrorCount { get; set; }
        public int WarningCount { get; set; }
        public int TotalCount { get; set; }
    }
}
