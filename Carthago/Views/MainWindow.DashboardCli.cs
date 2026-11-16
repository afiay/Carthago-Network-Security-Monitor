// SPDX-License-Identifier: MIT
using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Carthago.Cli;
using Carthago.Contracts;
using Carthago.Engine.Rules.Catalog;
using Carthago.Services.Cli;

namespace Carthago;

public partial class MainWindow
{
    private const int DashboardCliTranscriptLimit = 24000;
    private const int DashboardCliResultLimit = 12000;
    private CancellationTokenSource? _dashboardCliCancellation;

    private void InitializeDashboardCli()
    {
        DashboardCliOutput.Text =
            "CARTHAGO local CLI ready. Type help for supported read-only commands.\n" +
            "No external IPC endpoint, OS shell, or service control is started.";
        DashboardCliStatusText.Text = "READY · in-process read-only";
    }

    private void DashboardCliInput_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key != System.Windows.Input.Key.Enter) return;
        e.Handled = true;
        if (DashboardCliRunButton.IsEnabled)
            DashboardCliRun_Click(sender, new RoutedEventArgs());
    }

    private async void DashboardCliRun_Click(object sender, RoutedEventArgs e)
    {
        if (_dashboardCliCancellation is not null) return;

        var input = DashboardCliInput.Text.Trim();
        if (!GuiCliCommandPolicy.TryParse(input, out var args, out var localAction))
        {
            AppendDashboardCli("> " + input + "\nUnsupported command. Type help for the allowed read-only commands.");
            return;
        }

        DashboardCliInput.Clear();
        if (localAction == GuiCliLocalAction.Clear)
        {
            DashboardCliOutput.Clear();
            DashboardCliStatusText.Text = "READY · cleared";
            return;
        }
        if (localAction == GuiCliLocalAction.Help)
        {
            AppendDashboardCli("> help\n" + GuiCliCommandPolicy.HelpText);
            return;
        }

        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        _dashboardCliCancellation = cancellation;
        DashboardCliRunButton.IsEnabled = false;
        DashboardCliCancelButton.IsEnabled = true;
        DashboardCliStatusText.Text = "RUNNING · " + args[0];
        AppendDashboardCli("> carthago " + string.Join(" ", args));
        try
        {
            // Invoke the real CLI implementation rather than maintaining a
            // second command engine or requiring an opt-in named-pipe listener.
            // Only the explicit read-only policy is permitted here.
            var result = await Task.Run(async () =>
            {
                using var stdout = new StringWriter(CultureInfo.InvariantCulture);
                using var stderr = new StringWriter(CultureInfo.InvariantCulture);
                int exitCode = await CliApplication.RunAsync(args, stdout, stderr,
                    cancellation.Token,
                    query: (command, token) =>
                    {
                        token.ThrowIfCancellationRequested();
                        var now = DateTimeOffset.UtcNow;
                        var rules = command == ReadCommand.RulesSummary ? RuleCatalog.All : null;
                        return Task.FromResult(new ReadResponse(command, Guid.NewGuid(), ReadState.Available,
                            rules?.Count ?? 0,
                            rules?.Count(r => r.EnabledByDefault) ?? 0,
                            rules?.Count(r => r.IsPlanned) ?? 0, now));
                    },
                    liveQuery: CliLiveQueryHost.QueryAsync,
                    investigationQuery: CliInvestigationHost.QueryAsync);
                return (exitCode, stdout: stdout.ToString(), stderr: stderr.ToString());
            }, cancellation.Token);

            if (!_dashboardCallbackGate.IsOpen) return;
            if (!string.IsNullOrWhiteSpace(result.stdout))
                AppendDashboardCli(TruncateDashboardCliResult(result.stdout));
            if (!string.IsNullOrWhiteSpace(result.stderr))
                AppendDashboardCli(TruncateDashboardCliResult(result.stderr));
            DashboardCliStatusText.Text = result.exitCode == 0
                ? "COMPLETE · exit 0"
                : "FAILED · exit " + result.exitCode.ToString(CultureInfo.InvariantCulture);
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            if (_dashboardCallbackGate.IsOpen)
            {
                AppendDashboardCli("Command cancelled or exceeded 20-second limit.");
                DashboardCliStatusText.Text = "CANCELLED";
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            if (_dashboardCallbackGate.IsOpen)
            {
                AppendDashboardCli("CLI execution failed; no command side effects were requested.");
                DashboardCliStatusText.Text = "FAILED · execution unavailable";
            }
        }
        finally
        {
            _dashboardCliCancellation = null;
            if (_dashboardCallbackGate.IsOpen)
            {
                DashboardCliRunButton.IsEnabled = true;
                DashboardCliCancelButton.IsEnabled = false;
            }
        }
    }

    private static string TruncateDashboardCliResult(string value)
        => value.Length <= DashboardCliResultLimit
            ? value.TrimEnd()
            : value[..DashboardCliResultLimit].TrimEnd() + "\n[Output truncated]";

    private void AppendDashboardCli(string value)
    {
        var appended = DashboardCliOutput.Text + "\n" + value.TrimEnd() + "\n";
        DashboardCliOutput.Text = appended.Length <= DashboardCliTranscriptLimit
            ? appended
            : "[Earlier console output discarded]\n" + appended[^Math.Min(appended.Length, DashboardCliTranscriptLimit - 40)..];
        DashboardCliOutput.ScrollToEnd();
    }

    private void DashboardCliCancel_Click(object sender, RoutedEventArgs e)
        => _dashboardCliCancellation?.Cancel();

    private void DashboardCliClear_Click(object sender, RoutedEventArgs e)
    {
        DashboardCliOutput.Clear();
        if (_dashboardCliCancellation is null)
            DashboardCliStatusText.Text = "READY · cleared";
    }

    private void CleanupDashboardCli()
        => _dashboardCliCancellation?.Cancel();
}
