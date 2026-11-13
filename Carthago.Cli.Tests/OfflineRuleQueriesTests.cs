// SPDX-License-Identifier: MIT
using System.Text.Json;
using Carthago.Engine.Rules;
using Carthago.Services.SessionFiles;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class OfflineRuleQueriesTests
{
    [Theory]
    [InlineData("R001", true)]
    [InlineData("R999", true)]
    [InlineData("R1000", true)]
    [InlineData("R3085", true)]
    [InlineData("R2147483647", true)]
    [InlineData("R000", false)]
    [InlineData("R01000", false)]
    [InlineData("R100", true)]
    [InlineData("R2147483648", false)]
    [InlineData("R99999999999999999999", false)]
    [InlineData("R1000X", false)]
    [InlineData("R1000 ", false)]
    [InlineData("r1000", false)]
    [InlineData("OT001", false)]
    [InlineData("R١٠٠٠", false)]
    public void CanonicalCoreIdsOnly(string id, bool expected)
        => Assert.Equal(expected, OfflineRuleQueries.IsRuleId(id));

    [Fact]
    public void SharedComparerPreservesCoreAndPackOrder()
    {
        var ids = new[] { "R1000", "R999", "R001", "R3085", "OT001", "R101", "WEB001", "AD001" };
        Assert.Equal(new[] { "AD001", "OT001", "R001", "R101", "R999", "R1000", "R3085", "WEB001" },
            ids.OrderBy(id => id, RuleIdValidator.NumericComparer).ToArray());
        Assert.True(RuleIdValidator.TryGetCoreNumber("R1000", out int number));
        Assert.Equal(1000, number);
        Assert.False(RuleIdValidator.IsPackRuleId("R1000"));
        Assert.True(RuleIdValidator.IsPackRuleId("OT001"));
    }

    [Theory]
    [InlineData("R000")]
    [InlineData("R01000")]
    [InlineData("R2147483648")]
    public async Task NoncanonicalArchiveIdFailsClosed(string id)
    {
        string path = Temp(".csa");
        try
        {
            var snapshot = CarthagoSessionSnapshot.CreateEmpty();
            snapshot.AddRows("Rules", new[] { new { RuleId = "R1000" }, new { RuleId = id } });
            await new CarthagoSessionArchiveService().SaveAsync(path, snapshot);
            await Assert.ThrowsAsync<InvalidDataException>(() => OfflineRuleQueries.ListAsync(path, 0, 10, default));
        }
        finally { File.Delete(path); }
    }

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
            Assert.Equal("R1000", Assert.Single((await OfflineRuleQueries.ListAsync(path, 2, 1, default)).Rules).RuleId);
            Assert.Equal("R1000", (await OfflineRuleQueries.ShowAsync(path, "R1000", default))!.RuleId);
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
                "| R1000 | source | reviewed | passed | passed | passed | reviewed |\n");
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
