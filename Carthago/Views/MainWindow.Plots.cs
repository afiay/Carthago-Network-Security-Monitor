// File: Views/MainWindow.Plots.cs
using System;
using System.Collections.Generic;
using System.Linq;
using ScottPlot.WPF;

namespace Carthago
{
    public partial class MainWindow
    {
        // ======= Init Charts (ScottPlot v5 API) =======
        private void InitAllPlots()
        {
            ScottPlot.Color bg = ScottPlot.Color.FromHex("#0B1220");
            ScottPlot.Color panel = ScottPlot.Color.FromHex("#101826");
            ScottPlot.Color grid = ScottPlot.Color.FromHex("#223048");
            ScottPlot.Color ticks = ScottPlot.Color.FromHex("#9CA3AF");

            void StylePlot(WpfPlot wp)
            {
                wp.Plot.FigureBackground.Color = bg;
                wp.Plot.DataBackground.Color = panel;
                wp.Plot.Grid.MajorLineColor = grid;
                wp.Plot.Grid.MajorLineWidth = 1;
                wp.Plot.Axes.Color(ticks);
                wp.Plot.Legend.IsVisible = false;
            }

            // Traffic plots
            StylePlot(TrafficPlot);
            StylePlot(TrafficPlot_Analytics);
            TrafficPlot.Plot.Axes.DateTimeTicksBottom();
            TrafficPlot_Analytics.Plot.Axes.DateTimeTicksBottom();
            TrafficPlot.Plot.Title("Traffic Over Time");
            TrafficPlot.Plot.Axes.Bottom.Label.Text = "Time";
            TrafficPlot.Plot.Axes.Left.Label.Text = "Packets / sec";
            TrafficPlot.Plot.Legend.IsVisible = true;

            TrafficPlot_Analytics.Plot.Title("Traffic Over Time");
            TrafficPlot_Analytics.Plot.Axes.Bottom.Label.Text = "Time";
            TrafficPlot_Analytics.Plot.Axes.Left.Label.Text = "Packets / sec";
            TrafficPlot_Analytics.Plot.Legend.IsVisible = true;

            // Protocol / Talkers / Severity (both Dashboard and Analytics)
            void StyleBars(WpfPlot wp, string title, string xLab, string yLab, bool rotate = true)
            {
                StylePlot(wp);
                wp.Plot.Title(title);
                wp.Plot.Axes.Bottom.Label.Text = xLab;
                wp.Plot.Axes.Left.Label.Text = yLab;
                if (rotate)
                {
                    wp.Plot.Axes.Bottom.TickLabelStyle.Rotation = -45;
                    wp.Plot.Axes.Bottom.TickLabelStyle.Alignment = ScottPlot.Alignment.MiddleRight;
                }
            }

            StyleBars(ProtocolPlot, "Protocol Distribution", "Protocol", "Count");
            StyleBars(ProtocolPlot_Analytics, "Protocol Distribution", "Protocol", "Count");
            StyleBars(TopTalkersPlot, "Top Talkers (by Source)", "Source IP", "Packets");
            StyleBars(TopTalkersPlot_Analytics, "Top Talkers (by Source)", "Source IP", "Packets");

            StylePlot(SeverityPlot);
            SeverityPlot.Plot.Title("Alert Severity Distribution");
            StylePlot(SeverityPlot_Analytics);
            SeverityPlot_Analytics.Plot.Title("Alert Severity Distribution");

            // Overview sparklines visuals
            PrepareSpark(PpsSpark);
            PrepareSpark(ThroughputSpark);

            // seed with empties
            RenderTraffic();
            RenderProtocol();
            RenderTopTalkers();
            RenderSeverity();
            UpdateKpis();
        }

        // ======= Render helpers =======
        private static double[] MovingAverage(IReadOnlyList<double> ys, int window)
        {
            if (ys.Count == 0 || window <= 1) return Array.Empty<double>();
            window = Math.Min(window, ys.Count);
            double[] ma = new double[ys.Count - window + 1];
            double sum = 0;
            for (int i = 0; i < ys.Count; i++)
            {
                sum += ys[i];
                if (i >= window) sum -= ys[i - window];
                if (i >= window - 1) ma[i - (window - 1)] = sum / window;
            }
            return ma;
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

            void Draw(WpfPlot wp, bool withAverage)
            {
                wp.Plot.Clear();

                if (_trafficXs.Count > 1)
                {
                    // main line
                    var sp = wp.Plot.Add.Scatter(_trafficXs.ToArray(), _trafficYs.ToArray());
                    sp.MarkerSize = 0;
                    sp.LineWidth = 2;
                    sp.Color = ScottPlot.Color.FromHex("#60A5FA"); // blue
                    sp.LegendText = "PPS";

                    if (withAverage && _trafficYs.Count > 10)
                    {
                        // moving average overlay (10-sample window)
                        var ma = MovingAverage(_trafficYs, 10);
                        var maX = _trafficXs.Skip(_trafficXs.Count - ma.Length).ToArray();
                        var maPlot = wp.Plot.Add.Scatter(maX, ma);
                        maPlot.MarkerSize = 0;
                        maPlot.LineWidth = 2;
                        maPlot.LinePattern = ScottPlot.LinePattern.Dashed; // fixed
                        maPlot.Color = ScottPlot.Color.FromHex("#F59E0B"); // amber
                        maPlot.LegendText = "10-s MA"; // fixed (Label -> LegendText)
                        wp.Plot.Legend.IsVisible = true;
                    }
                }

                wp.Plot.Axes.Margins(bottom: 0);
                wp.Refresh();
            }

            Draw(TrafficPlot, withAverage: true);
            Draw(TrafficPlot_Analytics, withAverage: true);
        }

        private void RenderProtocol()
        {
            var ordered = _protocolCounts.OrderByDescending(kv => kv.Value).ToArray();
            var labels = ordered.Select(kv => kv.Key).ToArray();
            var values = ordered.Select(kv => (double)kv.Value).ToArray();
            var positions = Enumerable.Range(0, values.Length).Select(i => (double)i).ToArray();

            void Draw(WpfPlot wp)
            {
                wp.Plot.Clear();
                if (values.Length > 0)
                {
                    var bars = wp.Plot.Add.Bars(values);
                    for (int i = 0; i < bars.Bars.Count; i++)
                    {
                        bars.Bars[i].FillColor = ScottPlot.Color.FromHex(i < 3 ? "#34D399" : "#60A5FA");
                        bars.Bars[i].LineColor = bars.Bars[i].FillColor.Darken(.4); // fixed (BorderColor -> LineColor)
                        bars.Bars[i].Label = ((int)values[i]).ToString();
                    }
                    wp.Plot.Axes.Bottom.SetTicks(positions, labels);
                    wp.Plot.Axes.Margins(bottom: 0, top: .25);
                }
                wp.Refresh();
            }

            Draw(ProtocolPlot);
            Draw(ProtocolPlot_Analytics);
        }

        private void RenderTopTalkers()
        {
            var top = _talkerCounts
                .OrderByDescending(kv => kv.Value)
                .Take(10)
                .ToArray();

            var labels = top.Select(kv => kv.Key).ToArray();
            var values = top.Select(kv => (double)kv.Value).ToArray();
            var positions = Enumerable.Range(0, values.Length).Select(i => (double)i).ToArray();

            void Draw(WpfPlot wp)
            {
                wp.Plot.Clear();
                if (values.Length > 0)
                {
                    var bars = wp.Plot.Add.Bars(values);
                    for (int i = 0; i < bars.Bars.Count; i++)
                    {
                        bars.Bars[i].FillColor = ScottPlot.Color.FromHex("#93C5FD");
                        bars.Bars[i].LineColor = ScottPlot.Color.FromHex("#3B82F6"); // fixed
                        bars.Bars[i].Label = ((int)values[i]).ToString();
                    }
                    wp.Plot.Axes.Bottom.SetTicks(positions, labels);
                    wp.Plot.Axes.Margins(bottom: 0, top: .25);
                }
                wp.Refresh();
            }

            Draw(TopTalkersPlot);
            Draw(TopTalkersPlot_Analytics);
        }

        private void RenderSeverity()
        {
            string[] sevOrder = new[] { "Critical", "High", "Medium", "Low", "Info" };
            var colors = new Dictionary<string, ScottPlot.Color>
            {
                ["Critical"] = ScottPlot.Colors.Crimson,
                ["High"] = ScottPlot.Colors.OrangeRed,
                ["Medium"] = ScottPlot.Colors.Orange,
                ["Low"] = ScottPlot.Color.FromHex("#DAA520"),
                ["Info"] = ScottPlot.Colors.SteelBlue
            };

            List<ScottPlot.PieSlice> slices = new();
            foreach (var s in sevOrder)
            {
                double v = _severityCounts.TryGetValue(s, out var n) ? n : 0;
                slices.Add(new ScottPlot.PieSlice
                {
                    Value = v,
                    FillColor = colors[s],
                    Label = $"{s} ({v})"
                });
            }

            void Draw(WpfPlot wp)
            {
                wp.Plot.Clear();
                if (slices.Any(sl => sl.Value > 0))
                {
                    var pie = wp.Plot.Add.Pie(slices);
                    pie.ExplodeFraction = .06;
                    pie.SliceLabelDistance = 1.12;
                    pie.DonutFraction = .45;
                    slices.ForEach(x => x.LabelFontColor = x.FillColor.Darken(.45));
                }
                wp.Plot.Axes.Frameless();
                wp.Plot.HideGrid();
                wp.Refresh();
            }

            Draw(SeverityPlot);
            Draw(SeverityPlot_Analytics);
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

                // mean reference line
                double mean = ys.Average();
                var h = wp.Plot.Add.HorizontalLine(mean);
                h.LinePattern = ScottPlot.LinePattern.Dotted; // fixed
                h.LineWidth = 1;

                double ymax = Math.Max(1, ys.Max() * 1.15);
                wp.Plot.Axes.SetLimits(0, ys.Count - 1, 0, ymax);
            }

            wp.Refresh();
        }
    }
}
