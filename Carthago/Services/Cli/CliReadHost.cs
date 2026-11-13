// SPDX-License-Identifier: MIT
using Carthago.Contracts;
using Carthago.Engine.Rules.Catalog;

namespace Carthago.Services.Cli;

public static class CliReadHost
{
    public static ReadResponse Query(ReadRequest request)
    {
        var now = DateTimeOffset.UtcNow;
        if (request.Command == ReadCommand.HostStatus)
            return new ReadResponse(request.Command, request.Correlation, ReadState.Available, 0, 0, 0, now);
        if (request.Command == ReadCommand.RulesSummary)
        {
            var rules = RuleCatalog.All;
            return new ReadResponse(request.Command, request.Correlation, ReadState.Available,
                rules.Count, rules.Count(r => r.EnabledByDefault), rules.Count(r => r.IsPlanned), now);
        }
        return new ReadResponse(request.Command, request.Correlation, ReadState.Unavailable, 0, 0, 0, now);
    }
}
