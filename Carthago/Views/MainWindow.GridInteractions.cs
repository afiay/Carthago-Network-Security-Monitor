// SPDX-License-Identifier: MIT
// File: Views/MainWindow.GridInteractions.cs
// Shows JA4 family in HTTP/TLS section while keeping legacy JA3 visible.

using System;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Carthago.Models;

namespace Carthago
{
    public partial class MainWindow
    {
        private void TrafficGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (TrafficGrid.SelectedItem is not TrafficRecord r) return;

            var win = new Window
            {
                Title = "Packet Details",
                Owner = this,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Width = 860,
                Height = 720,
                MinWidth = 720,
                MinHeight = 520,
                ResizeMode = ResizeMode.CanResize,
                Background = new SolidColorBrush(Color.FromRgb(16, 24, 38))
            };

            var root = new Grid { Margin = new Thickness(12) };
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var header = BuildHeader(r);
            root.Children.Add(header);
            Grid.SetRow(header, 0);

            var scroll = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Margin = new Thickness(0, 10, 0, 10)
            };

            var content = new StackPanel { Orientation = Orientation.Vertical, Margin = new Thickness(2) };
            content.Children.Add(Section("Overview", BuildOverviewGrid(r)));
            content.Children.Add(Section("Endpoints", BuildEndpointGrid(r)));
            content.Children.Add(Section("WHOIS", BuildWhoisGrid(r)));
            content.Children.Add(Section("Reputation", BuildReputationGrid(r)));
            content.Children.Add(Section("HTTP / TLS", BuildHttpTlsGrid(r)));
            content.Children.Add(Section("DNS", BuildDnsGrid(r)));
            content.Children.Add(Section("Raw (payload / parser info)", BuildRawExpander(r)));

            scroll.Content = content;
            root.Children.Add(scroll);
            Grid.SetRow(scroll, 1);

            var actions = BuildActionsBar(r);
            root.Children.Add(actions);
            Grid.SetRow(actions, 2);

            win.Content = root;
            win.ShowDialog();
        }

        // ===== Section helpers =====

        private static Border Section(string title, UIElement inner)
        {
            return new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(16, 24, 38)),
                BorderBrush = new SolidColorBrush(Color.FromRgb(31, 41, 55)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Margin = new Thickness(0, 6, 0, 6),
                Padding = new Thickness(10),
                Child = new StackPanel
                {
                    Children =
                    {
                        new TextBlock
                        {
                            Text = title,
                            FontWeight = FontWeights.SemiBold,
                            Foreground = new SolidColorBrush(Color.FromRgb(229, 231, 235)),
                            Margin = new Thickness(2, 0, 0, 6)
                        },
                        inner
                    }
                }
            };
        }

        private static Grid BuildOverviewGrid(TrafficRecord r)
        {
            var g = Grid2Col();
            AddKV(g, "Timestamp", Safe(r.Timestamp));
            AddKV(g, "Protocol", Safe(r.Protocol));
            AddKV(g, "Protocol Version", Safe(r.ProtocolVersion));
            AddKV(g, "Service", Safe(r.ApplicationService));
            AddKV(g, "Flags", Safe(r.Flags));
            AddKV(g, "Length", r.Length.ToString());
            AddKV(g, "TTL", Safe(r.TTL));
            AddKV(g, "Process", $"{Safe(r.ProcessName)} (PID {SafeInt(r.ProcessId)})");
            AddKV(g, "Network Type", Safe(r.NetworkType));
            AddKV(g, "VPN/Proxy", $"{BoolIcon(r.IsVpn)} VPN / {BoolIcon(r.IsProxy)} Proxy");
            return g;
        }

        private static Grid BuildEndpointGrid(TrafficRecord r)
        {
            var g = Grid2Col();
            AddKV(g, "Source", $"{Safe(r.Source)}:{SafeInt(r.SourcePort)}");
            AddKV(g, "Destination", $"{Safe(r.Destination)}:{SafeInt(r.DestinationPort)}");
            AddKV(g, "MAC Src", Safe(r.MacSource));
            AddKV(g, "MAC Dst", Safe(r.MacDestination));
            return g;
        }

        private static Grid BuildWhoisGrid(TrafficRecord r)
        {
            var g = Grid2Col();
            AddKV(g, "Registrar", Safe(r.WhoisRegistrar));
            AddKV(g, "Organization", Safe(r.WhoisOrganization));
            AddKV(g, "Country", Safe(r.WhoisCountry));
            AddKV(g, "ASN", Safe(r.WhoisASN));
            AddKV(g, "Abuse Contact", Safe(r.WhoisAbuseContact));
            return g;
        }

        private static Grid BuildReputationGrid(TrafficRecord r)
        {
            var g = Grid2Col();
            AddKV(g, "Malicious", BoolIcon(r.ReputationIsMalicious));
            AddKV(g, "Score", SafeInt(r.ReputationScore));
            AddKV(g, "Reports", SafeInt(r.ReputationReports));
            AddKV(g, "Last Seen", r.ReputationLastSeen?.ToString("u") ?? "—");
            return g;
        }

        private static Grid BuildHttpTlsGrid(TrafficRecord r)
        {
            var g = Grid2Col();

            // --- HTTP fields ---
            AddKV(g, "HTTP Method", Safe(r.HttpMethod));
            AddKV(g, "HTTP Host", Safe(r.HttpHost));
            AddKV(g, "HTTP URI", Safe(r.HttpUri));
            AddKV(g, "User-Agent", Safe(r.HttpUserAgent));

            // --- TLS meta (aligned with PacketHandler assignments) ---
            AddKV(g, "SNI", Safe(r.Sni));                 // was TlsSni in older UI
            AddKV(g, "ALPN", Safe(r.Alpn));               // was TlsAlpn in older UI
            AddKV(g, "TLS Version", Safe(r.TlsVersion));

            // --- JA4 family (aligned with PacketHandler assignments) ---
            AddKV(g, "JA4", Safe(r.TlsJa4));              // client hello
            AddKV(g, "JA4S", Safe(r.TlsJa4s));            // server hello
            AddKV(g, "JA4H", Safe(r.HttpJa4h));           // HTTP
            AddKV(g, "JA4T / JA4TS", $"{Safe(r.TcpJa4t)} / {Safe(r.TcpJa4ts)}");  // TCP handshake
            AddKV(g, "JA4SSH / HASSH", $"{Safe(r.SshJa4)} / {Safe(r.Hassh)}");    // SSH
            AddKV(g, "JA4X (cert)", Safe(r.TlsJa4x));     // certificate
            AddKV(g, "JA4L / JA4LS", $"{Safe(r.Ja4L)} / {Safe(r.Ja4LS)}");        // latency  ← fixed names
            AddKV(g, "JA3 (legacy)", Safe(r.Ja3));

            // --- Optional cert UX (PacketHandler fills these if available) ---
            if (!string.IsNullOrWhiteSpace(r.CertSubject) ||
                !string.IsNullOrWhiteSpace(r.CertIssuer) ||
                r.CertValidFrom.HasValue || r.CertValidTo.HasValue)
            {
                AddKV(g, "Cert Subject", Safe(r.CertSubject));
                AddKV(g, "Cert Issuer", Safe(r.CertIssuer));
                AddKV(g, "Cert Valid From", r.CertValidFrom?.ToString("u") ?? "—");
                AddKV(g, "Cert Valid To", r.CertValidTo?.ToString("u") ?? "—");
            }

            return g;
        }

        private static Grid BuildDnsGrid(TrafficRecord r)
        {
            var g = Grid2Col();
            AddKV(g, "Query Name", Safe(r.DnsQname));
            AddKV(g, "Query Type", Safe(r.DnsQtype));
            AddKV(g, "RCode", Safe(r.DnsRcode));
            AddKV(g, "Is Response", r.DnsIsResponse.ToString());
            AddKV(g, "Answers", Safe(r.DnsAnswers));
            AddKV(g, "TTL", SafeInt(r.DnsTtl));
            return g;
        }

        private static UIElement BuildRawExpander(TrafficRecord r)
        {
            var tb = new TextBox
            {
                Text = r.Info ?? "",
                IsReadOnly = true,
                TextWrapping = TextWrapping.Wrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Background = new SolidColorBrush(Color.FromRgb(10, 15, 28)),
                Foreground = new SolidColorBrush(Color.FromRgb(229, 231, 235)),
                MinHeight = 120
            };
            return new Expander { Header = "Show raw info", Content = tb };
        }

        private Border BuildHeader(TrafficRecord r)
        {
            var br = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(15, 23, 42)),
                BorderBrush = new SolidColorBrush(Color.FromRgb(31, 41, 55)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(10)
            };

            var dp = new DockPanel();
            var title = new TextBlock
            {
                Text = $"{r.ApplicationService ?? r.Protocol} — {r.Source}:{r.SourcePort} → {r.Destination}:{r.DestinationPort}",
                FontWeight = FontWeights.SemiBold,
                Foreground = Brushes.White
            };
            dp.Children.Add(title);

            var pill = new Border
            {
                CornerRadius = new CornerRadius(999),
                Background = r.ReputationIsMalicious == true
                    ? new SolidColorBrush(Color.FromRgb(239, 68, 68))
                    : new SolidColorBrush(Color.FromRgb(59, 130, 246)),
                Padding = new Thickness(10, 4, 10, 4),
                Margin = new Thickness(8, 0, 0, 0)
            };
            pill.Child = new TextBlock
            {
                Text = r.ReputationIsMalicious == true ? "MALICIOUS" : $"Score {SafeInt(r.ReputationScore)}",
                Foreground = Brushes.White,
                FontWeight = FontWeights.Bold
            };
            DockPanel.SetDock(pill, Dock.Right);
            dp.Children.Add(pill);

            br.Child = dp;
            return br;
        }

        private UIElement BuildActionsBar(TrafficRecord r)
        {
            var bar = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            Button Btn(string text, Brush bg) => new()
            {
                Content = text,
                Margin = new Thickness(6, 10, 0, 0),
                Padding = new Thickness(12, 6, 12, 6),
                Background = bg,
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                Cursor = Cursors.Hand
            };

            var copyJson = Btn("Copy JSON", new SolidColorBrush(Color.FromRgb(59, 130, 246)));
            copyJson.Click += (_, _) => Clipboard.SetText(JsonSerializer.Serialize(r, new JsonSerializerOptions { WriteIndented = true }));

            var copySummary = Btn("Copy Summary", new SolidColorBrush(Color.FromRgb(59, 130, 246)));
            copySummary.Click += (_, _) =>
            {
                var sb = new StringBuilder();
                sb.AppendLine($"{r.Timestamp} {r.Protocol} {r.Source}:{r.SourcePort} → {r.Destination}:{r.DestinationPort}");
                sb.AppendLine($"Flags: {r.Flags}");
                sb.AppendLine($"WHOIS: {r.WhoisOrganization} ({r.WhoisCountry})");
                Clipboard.SetText(sb.ToString());
            };

            var openAbuse = Btn("AbuseIPDB", new SolidColorBrush(Color.FromRgb(59, 130, 246)));
            openAbuse.Click += (_, _) => { if (!string.IsNullOrWhiteSpace(r.Source)) OpenUrl($"https://www.abuseipdb.com/check/{r.Source}"); };

            var close = Btn("Close", new SolidColorBrush(Color.FromRgb(31, 41, 55)));
            close.Click += (s, _) => Window.GetWindow((DependencyObject)s!)?.Close();

            bar.Children.Add(copyJson);
            bar.Children.Add(copySummary);
            bar.Children.Add(openAbuse);
            bar.Children.Add(close);
            return bar;
        }

        // ===== Utility =====
        private static Grid Grid2Col()
        {
            var g = new Grid();
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(220) });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            return g;
        }

        private static void AddKV(Grid g, string key, string? val)
        {
            var row = g.RowDefinitions.Count;
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.Children.Add(new TextBlock { Text = key, Foreground = Brushes.LightGray, Margin = new Thickness(2, 3, 8, 3) });
            g.Children.Add(new TextBlock { Text = string.IsNullOrWhiteSpace(val) ? "—" : val, Foreground = Brushes.White, Margin = new Thickness(2, 3, 2, 3) });
            Grid.SetRow(g.Children[^2], row);
            Grid.SetColumn(g.Children[^2], 0);
            Grid.SetRow(g.Children[^1], row);
            Grid.SetColumn(g.Children[^1], 1);
        }

        private static string Safe(string? s) => string.IsNullOrWhiteSpace(s) ? "—" : s;
        private static string SafeInt(int? n) => n.HasValue ? n.Value.ToString() : "—";
        private static string BoolIcon(bool? b) => b == true ? "✔" : "—";

        private static void OpenUrl(string url)
        {
            try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
            catch (Exception ex) { MessageBox.Show($"Failed to open: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error); }
        }
    }
}
