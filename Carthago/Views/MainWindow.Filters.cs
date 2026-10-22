using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using Carthago.Models; // for TrafficRecord

namespace Carthago
{
    public partial class MainWindow
    {
        // ===== Traffic Filter =====
        private void TF_Apply_Click(object? sender, RoutedEventArgs e)
        {
            string search = SidebarPanel.TF_SearchText.Text.Trim();
            string src = SidebarPanel.TF_Src.Text.Trim();
            string dst = SidebarPanel.TF_Dst.Text.Trim();
            string proto = SidebarPanel.TF_Proto.Text.Trim();
            string port = SidebarPanel.TF_Port.Text.Trim();
            string ipVerSel = (SidebarPanel.TF_IpVer?.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Content?.ToString() ?? "Any";
            string l4MinText = SidebarPanel.TF_L4LenMin?.Text?.Trim() ?? "";
            int? l4Min = int.TryParse(l4MinText, out var _tmpL4) ? _tmpL4 : (int?)null;
            bool onlyMal = SidebarPanel.TF_OnlyMalicious.IsChecked == true;

            var view = CollectionViewSource.GetDefaultView(TrafficGrid.ItemsSource);
            if (view == null) return;

            view.Filter = o =>
            {
                if (o is not TrafficRecord r) return false;
                bool ok = true;

                if (!string.IsNullOrEmpty(search))
                {
                    var s = search.ToLowerInvariant();
                    ok &= (r.Source?.ToLowerInvariant().Contains(s) == true)
                        || (r.Flags?.ToLowerInvariant().Contains(s) == true)
                        || (r.Sni?.ToLowerInvariant().Contains(s) == true)
                        || (r.Alpn?.ToLowerInvariant().Contains(s) == true)
                        || (r.Ja4?.ToLowerInvariant().Contains(s) == true)
                        || (r.Ja4S?.ToLowerInvariant().Contains(s) == true)
                        || ((r.IpVersion?.ToString() ?? "").Contains(s))
                        || ((r.L4Len?.ToString() ?? "").Contains(s))
                        || (r.Destination?.ToLowerInvariant().Contains(s) == true)
                        || (r.Protocol?.ToLowerInvariant().Contains(s) == true)
                        || (r.ApplicationService?.ToLowerInvariant().Contains(s) == true)
                        || (r.WhoisOrganization?.ToLowerInvariant().Contains(s) == true)
                        || (r.WhoisCountry?.ToLowerInvariant().Contains(s) == true)
                        || (r.HttpHost?.ToLowerInvariant().Contains(s) == true)
                        || (r.HttpUri?.ToLowerInvariant().Contains(s) == true);
                }

                if (!string.IsNullOrEmpty(src)) ok &= r.Source?.Contains(src) == true;
                if (!string.IsNullOrEmpty(dst)) ok &= r.Destination?.Contains(dst) == true;
                if (!string.IsNullOrEmpty(proto)) ok &= string.Equals(r.Protocol, proto, StringComparison.OrdinalIgnoreCase);

                if (!string.IsNullOrEmpty(port) && int.TryParse(port, out int p))
                    ok &= (r.SourcePort == p || r.DestinationPort == p);


                // IP version filter
                if (!string.Equals(ipVerSel, "Any", StringComparison.OrdinalIgnoreCase))
                    ok &= r.IpVersion == (ipVerSel == "IPv4" ? 4 : 6);

                // L4 length minimum
                if (l4Min.HasValue)
                    ok &= (r.L4Len ?? 0) >= l4Min.Value;
                if (onlyMal) ok &= r.ReputationIsMalicious == true;

                return ok;
            };
            view.Refresh();
        }

        private void TF_Clear_Click(object? sender, RoutedEventArgs e)
        {
            SidebarPanel.TF_SearchText.Text = "";
            SidebarPanel.TF_Src.Text = "";
            SidebarPanel.TF_Dst.Text = "";
            SidebarPanel.TF_Proto.Text = "";
            SidebarPanel.TF_Port.Text = "";
            if (SidebarPanel.TF_IpVer != null) SidebarPanel.TF_IpVer.SelectedIndex = 0;
            if (SidebarPanel.TF_L4LenMin != null) SidebarPanel.TF_L4LenMin.Text = "";
            SidebarPanel.TF_OnlyMalicious.IsChecked = false;

            var view = CollectionViewSource.GetDefaultView(TrafficGrid.ItemsSource);
            if (view != null) { view.Filter = null; view.Refresh(); }
        }

        private void TF_UseAsBpf_Click(object? sender, RoutedEventArgs e)
        {
            string filter = SidebarPanel.TF_SearchText.Text.Trim();
            _captureService.ApplyFilter(filter);
        }


        // ===== Alerts / IDS Filter (type-agnostic via reflection) =====
        private void AF_Apply_Click(object? sender, RoutedEventArgs e)
        {
            string search = SidebarPanel.AF_SearchText.Text.Trim();
            string src = SidebarPanel.AF_Src.Text.Trim();
            string dst = SidebarPanel.AF_Dst.Text.Trim();
            string proto = SidebarPanel.AF_Proto.Text.Trim();
            string port = SidebarPanel.AF_Port.Text.Trim();
            string sevSel = (SidebarPanel.AF_Severity.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Any";

            var view = CollectionViewSource.GetDefaultView(AlertsGrid.ItemsSource);
            if (view == null) return;

            view.Filter = o =>
            {
                if (o is null) return false;
                bool ok = true;

                string ruleId = ReadString(o, "RuleId");
                string description = ReadString(o, "Description");
                string sourceIp = ReadString(o, "SourceIp");
                string destIp = ReadString(o, "DestinationIp");
                string protocol = ReadString(o, "Protocol");
                int? destPort = ReadInt(o, "DestinationPort");
                string severity = ReadString(o, "Severity");

                if (!string.IsNullOrEmpty(search))
                {
                    var s = search.ToLowerInvariant();
                    ok &= (ruleId?.ToLowerInvariant().Contains(s) == true)
                       || (description?.ToLowerInvariant().Contains(s) == true);
                }

                if (!string.IsNullOrEmpty(src)) ok &= sourceIp?.Contains(src) == true;
                if (!string.IsNullOrEmpty(dst)) ok &= destIp?.Contains(dst) == true;
                if (!string.IsNullOrEmpty(proto)) ok &= string.Equals(protocol, proto, StringComparison.OrdinalIgnoreCase);

                if (!string.IsNullOrEmpty(port) && int.TryParse(port, out int p))
                    ok &= destPort == p;

                if (!string.Equals(sevSel, "Any", StringComparison.OrdinalIgnoreCase))
                    ok &= string.Equals(severity, sevSel, StringComparison.OrdinalIgnoreCase);

                return ok;
            };
            view.Refresh();
        }

        private void AF_Clear_Click(object? sender, RoutedEventArgs e)
        {
            SidebarPanel.AF_SearchText.Text = "";
            SidebarPanel.AF_Src.Text = "";
            SidebarPanel.AF_Dst.Text = "";
            SidebarPanel.AF_Proto.Text = "";
            SidebarPanel.AF_Port.Text = "";
            SidebarPanel.AF_Severity.SelectedIndex = 0;

            var view = CollectionViewSource.GetDefaultView(AlertsGrid.ItemsSource);
            if (view != null) { view.Filter = null; view.Refresh(); }
        }

        // ===== Reflection helpers for type-agnostic alerts filtering =====
        private static string ReadString(object o, string propName)
        {
            try
            {
                var p = o.GetType().GetProperty(propName);
                var v = p?.GetValue(o);
                return v?.ToString() ?? string.Empty;
            }
            catch { return string.Empty; }
        }

        private static int? ReadInt(object o, string propName)
        {
            try
            {
                var p = o.GetType().GetProperty(propName);
                var v = p?.GetValue(o);
                if (v == null) return null;
                if (v is int i) return i;
                if (int.TryParse(v.ToString(), out int j)) return j;
                return null;
            }
            catch { return null; }
        }
    }
}
