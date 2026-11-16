// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Cli;
using Carthago.Contracts;
using Carthago.Services.Cli;
using Xunit;

namespace Carthago.Tests;

public sealed class GuiCliInProcessIntegrationTests
{
    [Fact]
    public async Task ReadOnlyRuleSummaryCallsRealCliApplicationWithoutNamedPipe()
    {
        Assert.True(GuiCliCommandPolicy.TryParse("rules summary", out var args, out var local));
        Assert.Equal(GuiCliLocalAction.None, local);
        using var output = new StringWriter();
        using var error = new StringWriter();
        var code = await CliApplication.RunAsync(args, output, error, CancellationToken.None,
            query: (kind, cancellation) =>
            {
                Assert.Equal(ReadCommand.RulesSummary, kind);
                return Task.FromResult(new ReadResponse(kind, Guid.NewGuid(), ReadState.Available,
                    3, 2, 1, DateTimeOffset.UtcNow));
            });
        Assert.Equal(0, code);
        Assert.Contains("Registered: 3", output.ToString());
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task LiveRuleListUsesActualLocalHostNotAnExternalIpcListener()
    {
        Assert.True(GuiCliCommandPolicy.TryParse("rules list --live --offset 0 --limit 1", out var args, out _));
        using var output = new StringWriter();
        using var error = new StringWriter();
        var code = await CliApplication.RunAsync(args, output, error, CancellationToken.None,
            liveQuery: CliLiveQueryHost.QueryAsync);
        Assert.Equal(0, code);
        Assert.Contains("Live registered catalog:", output.ToString());
        Assert.Equal(string.Empty, error.ToString());
    }
}
