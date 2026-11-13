// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Text.Json;
using System.Threading;
using Carthago.Contracts;

namespace Carthago;

public partial class MainWindow
{
    internal InvestigationPage? QueryCliInvestigation(InvestigationRequest request, CancellationToken token)
    {
        Dispatcher.VerifyAccess();
        token.ThrowIfCancellationRequested();
        // Project scalar metadata only. No raw payload, notes, evidence or mutation.
        switch (request.Kind)
        {
            case InvestigationKind.Incidents:
                if (_sinkHost is null) return null;
                return InvestigationProjection.Select(_sinkHost.Analytics.GetRecentIncidents(1000).Select(i =>
                    JsonSerializer.SerializeToElement(new { i.Id, i.UpdatedUtc, i.PrimaryRuleId, i.Severity,
                        i.PrimarySourceIp, i.PrimaryDestinationIp, i.Status, i.RiskScore, i.OccurrenceCount })),
                    request.Kind, request.Filter, token);
            case InvestigationKind.Events:
                return InvestigationProjection.Select(_traffic.GetRetainedSnapshot().Select(t =>
                    JsonSerializer.SerializeToElement(new { t.Id, t.Source, t.Destination, t.SourcePort,
                        t.DestinationPort, t.Protocol, t.Length })), request.Kind, request.Filter, token);
            case InvestigationKind.Hosts:
                if (_hostLastSeen.Count > 10000) return null;
                return InvestigationProjection.Select(_hostLastSeen.OrderBy(x => x.Key, StringComparer.Ordinal)
                    .Select(x => JsonSerializer.SerializeToElement(new { Host = x.Key, LastSeenUtc = x.Value })),
                    request.Kind, request.Filter, token);
            default: return null;
        }
    }
}
