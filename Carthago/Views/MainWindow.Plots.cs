// File: Views/MainWindow.Plots.cs
using System;
using System.Collections.Generic;
using System.Linq;
using ScottPlot.WPF;

namespace Carthago
{
    public partial class MainWindow
    {
        private const int TrafficAverageWindow = 10;

        // ======= Init Charts (ScottPlot v5 API) =======
        private void InitAllPlots()
        {
            ScottPlot.Color bg = ScottPlot.Color.FromHex("#07121F");
            ScottPlot.Color panel = ScottPlot.Color.FromHex("#091827");
            ScottPlot.Color grid = ScottPlot.Color.FromHex("#173149");
            ScottPlot.Color ticks = ScottPlot.Color.FromHex("#9CB3C4");

            void StylePlot(WpfPlot wp)
            {
                wp.Plot.FigureBackground.Color = bg;
                wp.Plot.DataBackground.Color = panel;
                wp.Plot.Grid.MajorLineColor = grid;
                wp.Plot.Grid.MajorLineWidth = 1;
                wp.Plot.Axes.Color(ticks);
                wp.Plot.Legend.IsVisible = false;
            }

            // Traffic plots use the same rolling local PPS sources.
            StylePlot(TrafficPlot);
            StylePlot(TrafficPlot_Analytics);
            TrafficPlot.Plot.Axes.DateTimeTicksBottom();
            TrafficPlot_Analytics.Plot.Axes.DateTimeTicksBottom();
            TrafficPlot.Plot.Axes.Bottom.Label.Text = "Time";
            TrafficPlot.Plot.Axes.Left.Label.Text = "Packets / sec";
            TrafficPlot_Analytics.Plot.Axes.Bottom.Label.Text = "Time";
            TrafficPlot_Analytics.Plot.Axes.Left.Label.Text = "Packets / sec";

            // Analytics-only charts are styled at startup, but data rendering is deferred
            // until the Analytics workspace is visible.
            void StyleBars(WpfPlot wp, string xLab, string yLab)
            {
                StylePlot(wp);
                wp.Plot.Axes.Bottom.Label.Text = xLab;
                wp.Plot.Axes.Left.Label.Text = yLab;
            }

            StyleBars(ProtocolPlot_Analytics, "Observed packets", "Protocol");
            StyleBars(TopTalkersPlot_Analytics, "Packets", "Source IP");

            StylePlot(SeverityPlot_Analytics);

            // Hidden compatibility plots remain initialized but are not redrawn in the hot path.
            StylePlot(ProtocolPlot);
            StylePlot(TopTalkersPlot);
            StylePlot(SeverityPlot);
            PrepareSpark(PpsSpark);
            PrepareSpark(ThroughputSpark);

            RenderTraffic();
            UpdateKpis();
        }

        // Compute the 10-sample average once when the timer appends a sample.
        // This avoids allocating and recomputing a complete moving-average series on every chart redraw.
        private void AppendTrafficAverage(double x)
        {
            if (_trafficYs.Count < TrafficAverageWindow)
                return;

            double sum = 0;
            for (int i = _trafficYs.Count - TrafficAverageWindow; i < _trafficYs.Count; i++)
                sum += _trafficYs[i];

            _trafficAverageXs.Add(x);
            _trafficAverageYs.Add(sum / TrafficAverageWindow);
        }

        private void TrimTrafficAverageToWindow()
        {
            if (_trafficXs.Count == 0)
            {
                _trafficAverageXs.Clear();
                _trafficAverageYs.Clear();
                return;
            }

            double oldestVisibleX = _trafficXs[0];
            while (_trafficAverageXs.Count > 0 && _trafficAverageXs[0] < oldestVisibleX)
            {
                _trafficAverageXs.RemoveAt(0);
                _trafficAverageYs.RemoveAt(0);
            }
        }

        private void RenderTraffic()
        {
            // The existing timer can append zeros when capture is inactive.
            // A timer sample is not proof of capture health or network-wide visibility.
            int sampleCount = _trafficYs.Count;
            DashboardTrafficChartWaitingPanel.Visibility = sampleCount < 2
                ? System.Windows.Visibility.Visible
                : System.Windows.Visibility.Collapsed;
            string captureStatus = CaptureStatusText.Text ?? "Unknown";
            DashboardTrafficChartTextSummary.Text = sampleCount == 0
                ? $"No local PPS timer samples yet. Capture status: {captureStatus}. No packet-rate observation is available."
                : $"Latest local timer PPS sample: {_trafficYs[^1]:0} packets/s; {sampleCount} of {TrafficWindowSeconds} retained samples. Capture status: {captureStatus}. Timer zeros can occur without active capture.";

            void Draw(WpfPlot wp)
            {
                wp.Plot.Clear();

                if (_trafficXs.Count > 1)
                {
                    // SignalXY is optimized for ascending X/Y data and can consume the rolling lists directly.
                    // This removes the former ToArray allocations on every redraw.
                    var pps = wp.Plot.Add.SignalXY(_trafficXs, _trafficYs);
                    pps.MarkerSize = 0;
                    pps.LineWidth = 2;
                    pps.Color = ScottPlot.Color.FromHex("#31D4E7");
                    pps.LegendText = "Local PPS";

                    if (_trafficAverageYs.Count > 1)
                    {
                        var average = wp.Plot.Add.SignalXY(_trafficAverageXs, _trafficAverageYs);
                        average.MarkerSize = 0;
                        average.LineWidth = 2;
                        average.LinePattern = ScottPlot.LinePattern.Dashed;
                        average.Color = ScottPlot.Color.FromHex("#F4B860");
                        average.LegendText = "10-sample average";
                    }
                }

                wp.Plot.Axes.Margins(bottom: 0, top: .12);
                wp.Plot.Axes.AutoScale();
                wp.Refresh();
            }

            if (DashboardView.IsVisible)
                Draw(TrafficPlot);
            if (AnalyticsView.IsVisible)
                Draw(TrafficPlot_Analytics);
        }

        private void RenderProtocol()
        {
            if (!AnalyticsView.IsVisible)
                return;

            // Ascending values place the largest category at the top of a horizontal bar chart.
            var ordered = _protocolCounts
                .OrderBy(kv => kv.Value)
                .ToArray();
            var labels = ordered.Select(kv => kv.Key).ToArray();
            var values = ordered.Select(kv => (double)kv.Value).ToArray();
            var positions = Enumerable.Range(0, values.Length).Select(i => (double)i).ToArray();

            var wp = ProtocolPlot_Analytics;
            wp.Plot.Clear();
            if (values.Length > 0)
            {
                var bars = wp.Plot.Add.Bars(values);
                bars.Horizontal = true;
                for (int i = 0; i < bars.Bars.Count; i++)
                {
                    bool topTier = i >= Math.Max(0, bars.Bars.Count - 3);
                    bars.Bars[i].FillColor = ScottPlot.Color.FromHex(topTier ? "#2FCAD8" : "#1C7892");
                    bars.Bars[i].LineColor = ScottPlot.Color.FromHex(topTier ? "#62E4EE" : "#2A9BB3");
                    bars.Bars[i].Label = ((int)values[i]).ToString();
                }
                wp.Plot.Axes.Left.SetTicks(positions, labels);
                wp.Plot.Axes.Margins(left: 0, right: .18);
                wp.Plot.Axes.AutoScale();
            }
            wp.Refresh();
        }

        private void RenderTopTalkers()
        {
            if (!AnalyticsView.IsVisible)
                return;

            // Keep the existing Top 10 scope, but render horizontally so source addresses stay readable.
            var top = _talkerCounts
                .OrderByDescending(kv => kv.Value)
                .Take(10)
                .OrderBy(kv => kv.Value)
                .ToArray();

            var labels = top.Select(kv => kv.Key).ToArray();
            var values = top.Select(kv => (double)kv.Value).ToArray();
            var positions = Enumerable.Range(0, values.Length).Select(i => (double)i).ToArray();

            var wp = TopTalkersPlot_Analytics;
            wp.Plot.Clear();
            if (values.Length > 0)
            {
                var bars = wp.Plot.Add.Bars(values);
                bars.Horizontal = true;
                for (int i = 0; i < bars.Bars.Count; i++)
                {
                    bars.Bars[i].FillColor = ScottPlot.Color.FromHex("#2399AF");
                    bars.Bars[i].LineColor = ScottPlot.Color.FromHex("#4BD7E4");
                    bars.Bars[i].Label = ((int)values[i]).ToString();
                }
                wp.Plot.Axes.Left.SetTicks(positions, labels);
                wp.Plot.Axes.Margins(left: 0, right: .18);
                wp.Plot.Axes.AutoScale();
            }
            wp.Refresh();
        }

        private void RenderSeverity()
        {
            if (!AnalyticsView.IsVisible)
                return;

            string[] sevOrder = new[] { "Critical", "High", "Medium", "Low", "Info" };
            var colors = new Dictionary<string, ScottPlot.Color>
            {
                ["Critical"] = ScottPlot.Color.FromHex("#F0525C"),
                ["High"] = ScottPlot.Color.FromHex("#F28C45"),
                ["Medium"] = ScottPlot.Color.FromHex("#E9B949"),
                ["Low"] = ScottPlot.Color.FromHex("#55B77A"),
                ["Info"] = ScottPlot.Color.FromHex("#3AA9C7")
            };

            List<ScottPlot.PieSlice> slices = new();
            foreach (var s in sevOrder)
            {
                double v = _severityCounts.TryGetValue(s, out var n) ? n : 0;
                slices.Add(new ScottPlot.PieSlice
                {
                    Value = v,
                    FillColor = colors[s],
                    Label = $"{s} ({v})",
                    LabelFontColor = ScottPlot.Color.FromHex("#DDEAF3")
                });
            }

            var wp = SeverityPlot_Analytics;
            wp.Plot.Clear();
            if (slices.Any(sl => sl.Value > 0))
            {
                var pie = wp.Plot.Add.Pie(slices);
                pie.ExplodeFraction = 0;
                pie.SliceLabelDistance = 1.05;
                pie.DonutFraction = .62;
            }
            wp.Plot.Axes.Frameless();
            wp.Plot.HideGrid();
            wp.Refresh();
        }

        // ===== KPI: Overview =====
        private static void PrepareSpark(WpfPlot wp)
        {
            wp.Plot.Clear();
            wp.Plot.Axes.Frameless();
            wp.Plot.HideGrid();
        }

        private void RenderSpark(WpfPlot wp, IReadOnlyList<double> ys)
        {
            PrepareSpark(wp);

            if (ys.Count > 1)
            {
                var sig = wp.Plot.Add.Signal(ys.ToArray());
                sig.LineWidth = 2;
                sig.Color = ScottPlot.Color.FromHex("#31D4E7");

                // mean reference line
                double mean = ys.Average();
                var h = wp.Plot.Add.HorizontalLine(mean);
                h.LinePattern = ScottPlot.LinePattern.Dotted;
                h.LineWidth = 1;
                h.Color = ScottPlot.Color.FromHex("#5E8195");

                double ymax = Math.Max(1, ys.Max() * 1.15);
                wp.Plot.Axes.SetLimits(0, ys.Count - 1, 0, ymax);
            }

            wp.Refresh();
        }
    }
}
