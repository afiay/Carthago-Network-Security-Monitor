// SPDX-License-Identifier: MIT
using System.Text.Json;
using Carthago.Services.SessionFiles;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class OfflineRuleQueriesTests
{
    [Fact]
    public async Task ListUsesNumericOrderAndBoundedPage()
    {
        string path = Temp(".csa");
        try
        {
            var snapshot = CarthagoSessionSnapshot.CreateEmpty();
            snapshot.AddRows("Rules", new[] { new { RuleId = "R1000", RuleName = "Fourth" },
                new { RuleId = "R999", RuleName = "Third" }, new { RuleId = "R001", RuleName = "First" } });
            await new CarthagoSessionArchiveService().SaveAsync(path, snapshot);
            var page = await OfflineRuleQueries.ListAsync(path, 1, 1, default);
            Assert.Equal(3, page.Total);
            Assert.Equal("R999", Assert.Single(page.Rules).RuleId);
            Assert.Empty((await OfflineRuleQueries.ListAsync(path, 99, 1, default)).Rules);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task ShowProjectsOnlyAllowlistedMetadata()
    {
        string path = Temp(".csa");
        try
        {
            var snapshot = CarthagoSessionSnapshot.CreateEmpty();
            snapshot.AddRows("Rules", new[] { new { RuleId = "R001", RuleName = "Name", Category = "Network",
                EnabledByDefault = false, IsPlanned = true, Revision = 2, Description = "PRIVATE-EVIDENCE",
                SignalKind = "\u001b[31m" } });
            await new CarthagoSessionArchiveService().SaveAsync(path, snapshot);
            var rule = await OfflineRuleQueries.ShowAsync(path, "R001", default);
            Assert.NotNull(rule);
            Assert.False(rule!.EnabledByDefault);
            Assert.True(rule.IsPlanned);
            Assert.Null(rule.SignalKind);
            Assert.DoesNotContain("PRIVATE-EVIDENCE", JsonSerializer.Serialize(rule));
            Assert.Null(await OfflineRuleQueries.ShowAsync(path, "R002", default));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task DuplicateRulesFailClosed()
    {
        string path = Temp(".csa");
        try
        {
            var snapshot = CarthagoSessionSnapshot.CreateEmpty();
            snapshot.AddRows("Rules", new[] { new { RuleId = "R001" }, new { RuleId = "R001" } });
            await new CarthagoSessionArchiveService().SaveAsync(path, snapshot);
            await Assert.ThrowsAsync<InvalidDataException>(() => OfflineRuleQueries.ListAsync(path, 0, 10, default));
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData("-1", "10")]
    [InlineData("0", "0")]
    [InlineData("0", "101")]
    [InlineData("999999999999999999", "10")]
    public void InvalidPageRejected(string offset, string limit)
        => Assert.False(OfflineRuleQueries.TryPage(offset, limit, out _, out _));

    [Fact]
    public async Task QualityCountsLabelsNotTests()
    {
        string path = Temp(".md");
        try
        {
            await File.WriteAllTextAsync(path, Header +
                "| R001 | source | pending | pending | pending | pending | audit pending |\n" +
                "| R002 | source | missing | none | none | none | producer-blocked; tests unexecuted |\n" +
                "| R003 | source | reviewed | passed | passed | passed | reviewed |\n");
            var quality = await OfflineRuleQueries.QualityAsync(path, default);
            Assert.Equal(3, quality.LedgerRows);
            Assert.Equal(1, quality.AuditPending);
            Assert.Equal(1, quality.ProducerBlocked);
            Assert.Equal(1, quality.OtherOrUnclassified);
            Assert.Equal("not_assessed", quality.Validation);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task DuplicateLedgerRowsFailClosed()
    {
        string path = Temp(".md");
        try
        {
            string row = "| R001 | source | pending | pending | pending | pending | audit pending |\n";
            await File.WriteAllTextAsync(path, Header + row + row);
            await Assert.ThrowsAsync<InvalidDataException>(() => OfflineRuleQueries.QualityAsync(path, default));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task InvalidCliPageUsesStderr()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        int code = await CliApplication.RunAsync(new[] { "rules", "list", "x.csa", "--offset", "0", "--limit", "101", "--json" }, output, error);
        Assert.Equal(2, code);
        Assert.Empty(output.ToString());
        Assert.Contains("invalid_usage", error.ToString());
    }

    private const string Header = "| Rule | Implementation | Producer | Positive | Negative | Boundary | Status/blocker |\n|---|---|---|---|---|---|---|\n";
    private static string Temp(string ext) => Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ext);
}
