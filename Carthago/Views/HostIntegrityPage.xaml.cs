// SPDX-License-Identifier: MIT
// File: Views/HostIntegrityPage.xaml.cs
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Carthago.Services;

namespace Carthago.Views
{
    public partial class HostIntegrityPage : Page
    {
        private readonly RootkitDetectorService _rootkitService = new();
        private readonly InstalledSoftwareInventoryService _appService = new();

        private List<RootkitDetectorService.DriverRecord> _allDrivers = new();
        private List<InstalledSoftwareInventoryService.InstalledAppRecord> _allApps = new();

        private DateTimeOffset? _driverScanTime;
        private DateTimeOffset? _appScanTime;

        public HostIntegrityPage()
        {
            InitializeComponent();
            Loaded += HostIntegrityPage_Loaded;
        }

        private async void HostIntegrityPage_Loaded(object sender, RoutedEventArgs e)
        {
            // Run once on first load
            Loaded -= HostIntegrityPage_Loaded;
            await RefreshAllAsync();
        }

        // ===== SCAN & REFRESH =====

        private async Task RefreshAllAsync()
        {
            try
            {
                if (RescanButton != null)
                    RescanButton.IsEnabled = false;

                if (SummaryText != null)
                    SummaryText.Text = "Scanning drivers and installed software...";

                Mouse.OverrideCursor = Cursors.Wait;

                // Run both scans on background threads
                var driverTask = Task.Run(() => _rootkitService.Scan());
                var appTask = Task.Run(() => _appService.Scan());

                var driverResult = await driverTask.ConfigureAwait(true);
                var appResult = await appTask.ConfigureAwait(true);

                _allDrivers = driverResult.Drivers ?? new List<RootkitDetectorService.DriverRecord>();
                _driverScanTime = driverResult.ScanTime;

                _allApps = appResult.Apps ?? new List<InstalledSoftwareInventoryService.InstalledAppRecord>();
                _appScanTime = appResult.ScanTime;

                UpdateDriverGrid();
                UpdateAppGrid();
                UpdateSummary();
            }
            catch (Exception ex)
            {
                var msg = "Host integrity scan failed:\n" + ex.Message;

                // If we have a parent window, use it as owner; otherwise a normal MessageBox
                var owner = Window.GetWindow(this);
                if (owner != null)
                {
                    MessageBox.Show(
                        owner,
                        msg,
                        "Host Integrity",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                }
                else
                {
                    MessageBox.Show(
                        msg,
                        "Host Integrity",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                }
            }
            finally
            {
                Mouse.OverrideCursor = null;
                if (RescanButton != null)
                    RescanButton.IsEnabled = true;
            }
        }

        private void UpdateDriverGrid()
        {
            if (DriversGrid == null)
                return;

            IEnumerable<RootkitDetectorService.DriverRecord> query = _allDrivers;

            if (ShowOnlySuspiciousDriversCheck?.IsChecked == true)
                query = query.Where(IsSuspiciousDriver);

            DriversGrid.ItemsSource = query
                .OrderByDescending(d => d.Score)
                .ThenBy(d => d.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private void UpdateAppGrid()
        {
            if (AppsGrid == null)
                return;

            IEnumerable<InstalledSoftwareInventoryService.InstalledAppRecord> query = _allApps;

            if (ShowOnlySuspiciousAppsCheck?.IsChecked == true)
                query = query.Where(IsSuspiciousApp);

            AppsGrid.ItemsSource = query
                .OrderByDescending(a => a.Score)
                .ThenBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private void UpdateSummary()
        {
            int maxDriverScore = _allDrivers.Count != 0 ? _allDrivers.Max(d => d.Score) : 0;
            int maxAppScore = _allApps.Count != 0 ? _allApps.Max(a => a.Score) : 0;
            int hostScore = Math.Max(maxDriverScore, maxAppScore);

            int suspiciousDrivers = _allDrivers.Count(IsSuspiciousDriver);
            int suspiciousApps = _allApps.Count(IsSuspiciousApp);

            if (HostScoreText != null)
                HostScoreText.Text = hostScore.ToString();

            if (HostRiskText != null)
                HostRiskText.Text = ScoreToRisk(hostScore);

            if (SummaryText != null)
            {
                SummaryText.Text =
                    $"Drivers: {_allDrivers.Count} total, {suspiciousDrivers} suspicious | " +
                    $"Apps: {_allApps.Count} total, {suspiciousApps} suspicious";
            }

            if (ScanTimeText != null)
            {
                var dtDriver = _driverScanTime?.ToLocalTime().ToString("u") ?? "-";
                var dtApp = _appScanTime?.ToLocalTime().ToString("u") ?? "-";
                ScanTimeText.Text = $"Driver scan: {dtDriver} | App scan: {dtApp}";
            }
        }

        private static string ScoreToRisk(int score)
        {
            if (score >= 80) return "High";
            if (score >= 50) return "Medium";
            if (score >= 20) return "Low";
            return "Info";
        }

        private static bool IsSuspiciousDriver(RootkitDetectorService.DriverRecord d)
        {
            if (d == null) return false;

            // Strong indicators: unsigned kernel + running + weird path, or high score
            return d.Score >= 50 || d.SuspiciousPath || d.SuspiciousUnsigned;
        }

        private static bool IsSuspiciousApp(InstalledSoftwareInventoryService.InstalledAppRecord a)
        {
            if (a == null) return false;

            // Some categories are normally expected on a power-user machine.
            bool isTrustedCategory =
                string.Equals(a.Category, "DevTool", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(a.Category, "Security", StringComparison.OrdinalIgnoreCase);

            // 1) Absolute red flags – always show
            if (a.IsRemoteAccessTool && a.ExposureScore >= 20)
                return true;

            // 2) Very high overall score
            if (a.Score >= 70)
                return true;

            // 3) High-exposure stuff living in user space, but *not* dev tools / AV
            if (!isTrustedCategory &&
                a.ExposureScore >= 40 &&
                (a.UserWritableLocation || a.IsPerUserInstall))
                return true;

            // 4) Hygiene problems on old software:
            //    - missing version / weird publisher already folded into HygieneScore
            //    - older than ~90 days
            if (a.HygieneScore >= 40 && a.AgeInDays > 90)
                return true;

            // 5) Default: trusted categories are hidden unless really extreme
            if (isTrustedCategory)
                return false;

            return false;
        }
        private static bool IsCleanupCandidate(InstalledSoftwareInventoryService.InstalledAppRecord a)
        {
            if (a == null) return false;

            // Don’t propose cleaning system components, dev tools, or security products by default
            if (a.IsSystemComponent) return false;
            if (string.Equals(a.Category, "DevTool", StringComparison.OrdinalIgnoreCase)) return false;
            if (string.Equals(a.Category, "Security", StringComparison.OrdinalIgnoreCase)) return false;

            // Strong signals of "junk" or low-value:
            bool looksOld = a.AgeInDays >= 180 && a.AgeInDays != -1;
            bool isUserSpace = a.UserWritableLocation || a.IsPerUserInstall;

            // Candidates:
            //  - old, user-space, medium+ score
            //  - OR missing version + not a well-known vendor
            if ((looksOld && isUserSpace && a.Score >= 40) ||
                (a.HygieneScore >= 30 && isUserSpace))
            {
                return true;
            }

            return false;
        }

        // ===== UI handlers =====

        private async void RescanButton_Click(object sender, RoutedEventArgs e)
        {
            await RefreshAllAsync();
        }

        private void ShowOnlySuspiciousDriversCheck_Changed(object sender, RoutedEventArgs e)
        {
            UpdateDriverGrid();
        }

        private void ShowOnlySuspiciousAppsCheck_Changed(object sender, RoutedEventArgs e)
        {
            UpdateAppGrid();
        }

        // ===== Driver actions =====

        private void OpenDriverLocation_Click(object sender, RoutedEventArgs e)
        {
            if (DriversGrid?.SelectedItem is not RootkitDetectorService.DriverRecord rec)
                return;

            if (string.IsNullOrWhiteSpace(rec.Path))
                return;

            OpenInExplorer(rec.Path);
        }

        private void CopyDriverPath_Click(object sender, RoutedEventArgs e)
        {
            if (DriversGrid?.SelectedItem is not RootkitDetectorService.DriverRecord rec)
                return;

            if (string.IsNullOrWhiteSpace(rec.Path))
                return;

            SafeSetClipboard(rec.Path);
        }

        // ===== App actions =====

        private void OpenAppLocation_Click(object sender, RoutedEventArgs e)
        {
            if (AppsGrid?.SelectedItem is not InstalledSoftwareInventoryService.InstalledAppRecord app)
                return;

            if (string.IsNullOrWhiteSpace(app.InstallLocation))
                return;

            OpenInExplorer(app.InstallLocation);
        }

        private void CopyUninstallString_Click(object sender, RoutedEventArgs e)
        {
            if (AppsGrid?.SelectedItem is not InstalledSoftwareInventoryService.InstalledAppRecord app)
                return;

            if (string.IsNullOrWhiteSpace(app.UninstallString))
                return;

            SafeSetClipboard(app.UninstallString);
        }

        private void UninstallApp_Click(object sender, RoutedEventArgs e)
        {
            if (AppsGrid?.SelectedItem is not InstalledSoftwareInventoryService.InstalledAppRecord app)
                return;

            try
            {
                var plan = _appService.BuildUninstallPlan(app);

                if (!plan.CanUninstall)
                {
                    string reason = string.IsNullOrWhiteSpace(plan.Reason)
                        ? "This application cannot be uninstalled from here."
                        : plan.Reason;

                    var owner = Window.GetWindow(this);
                    if (owner != null)
                    {
                        MessageBox.Show(
                            owner,
                            reason,
                            "Uninstall",
                            MessageBoxButton.OK,
                            MessageBoxImage.Information);
                    }
                    else
                    {
                        MessageBox.Show(
                            reason,
                            "Uninstall",
                            MessageBoxButton.OK,
                            MessageBoxImage.Information);
                    }
                    return;
                }

                string details = plan.FileName ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(plan.Arguments))
                    details += " " + plan.Arguments;

                string extra = string.Empty;
                if (plan.RequiresElevationHint)
                    extra = "\n\nThis will likely prompt for administrator approval (UAC).";

                string msg =
                    $"Do you want to uninstall '{app.Name}'?\n\n" +
                    $"Command:\n{details}{extra}";

                var ownerWindow = Window.GetWindow(this);
                var result = ownerWindow != null
                    ? MessageBox.Show(ownerWindow, msg, "Confirm uninstall", MessageBoxButton.YesNo, MessageBoxImage.Warning)
                    : MessageBox.Show(msg, "Confirm uninstall", MessageBoxButton.YesNo, MessageBoxImage.Warning);

                if (result != MessageBoxResult.Yes)
                    return;

                if (!_appService.TryLaunchUninstall(app, out var error))
                {
                    string emsg = "Failed to launch uninstall.";
                    if (error != null) emsg += "\n\n" + error.Message;

                    if (ownerWindow != null)
                    {
                        MessageBox.Show(
                            ownerWindow,
                            emsg,
                            "Uninstall",
                            MessageBoxButton.OK,
                            MessageBoxImage.Error);
                    }
                    else
                    {
                        MessageBox.Show(
                            emsg,
                            "Uninstall",
                            MessageBoxButton.OK,
                            MessageBoxImage.Error);
                    }

                    return;
                }

                if (SummaryText != null)
                    SummaryText.Text = $"Uninstall started for '{app.Name}'. It may take a moment to complete.";
            }
            catch (Exception ex)
            {
                var emsg = "Uninstall failed to start:\n" + ex.Message;
                var owner = Window.GetWindow(this);

                if (owner != null)
                {
                    MessageBox.Show(
                        owner,
                        emsg,
                        "Uninstall",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                }
                else
                {
                    MessageBox.Show(
                        emsg,
                        "Uninstall",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                }
            }
        }

        // ===== helpers =====

        private static void OpenInExplorer(string path)
        {
            try
            {
                string full = path;
                try
                {
                    full = Path.GetFullPath(path);
                }
                catch
                {
                    // ignore path normalization issues
                }

                if (File.Exists(full))
                {
                    var args = "/select,\"" + full + "\"";
                    Process.Start(new ProcessStartInfo("explorer.exe", args)
                    {
                        UseShellExecute = true
                    });
                }
                else if (Directory.Exists(full))
                {
                    Process.Start(new ProcessStartInfo("explorer.exe", "\"" + full + "\"")
                    {
                        UseShellExecute = true
                    });
                }
                else
                {
                    var dir = Path.GetDirectoryName(full);
                    if (!string.IsNullOrWhiteSpace(dir) && Directory.Exists(dir))
                    {
                        Process.Start(new ProcessStartInfo("explorer.exe", "\"" + dir + "\"")
                        {
                            UseShellExecute = true
                        });
                    }
                }
            }
            catch
            {
                // Swallow – you don't want UI death because Explorer failed.
            }
        }

        private static void SafeSetClipboard(string text)
        {
            try
            {
                Clipboard.SetText(text);
            }
            catch
            {
                // Can fail in RDP / low integrity – ignore.
            }
        }
    }
}
