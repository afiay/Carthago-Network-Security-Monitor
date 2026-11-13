// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using Carthago.Contracts;

namespace Carthago.Services.Cli;

internal static class CliInvestigationHost
{
    internal static async Task<InvestigationResponse> QueryAsync(InvestigationRequest request, CancellationToken token)
    {
        InvestigationProtocol.ValidateRequest(request);
        var now = DateTimeOffset.UtcNow;
        InvestigationPage? page;
        if (request.Kind == InvestigationKind.Alerts)
        {
            page = await DetectionJournalQuery.ReadAsync(DetectionJournal.Current.GetJournalPath(now.UtcDateTime),
                request.Filter, token).ConfigureAwait(false);
        }
        else
        {
            var app = Application.Current;
            if (app is null || app.Dispatcher.HasShutdownStarted) page = null;
            else page = await app.Dispatcher.InvokeAsync(() =>
                app.MainWindow is MainWindow window ? window.QueryCliInvestigation(request, token) : null,
                DispatcherPriority.Background, token).Task.ConfigureAwait(false);
        }
        return new InvestigationResponse(InvestigationProtocol.Version, request.Correlation, request.Kind,
            page is null ? LiveQueryState.Unavailable : LiveQueryState.Available, now, page);
    }
}
