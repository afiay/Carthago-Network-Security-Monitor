// SPDX-License-Identifier: MIT
using System.IO.Compression;
using System.Text.Json;
using Carthago.Cli;
using Carthago.Services.SessionFiles;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class CliApplicationTests
{
    [Fact]
    public async Task HelpDocumentsOnlyImplementedCommands()
    {
        var result = await Run("--help");
        Assert.Equal(0, result.Code);
        Assert.Contains("session inspect", result.Out);
        Assert.Empty(result.Error);
    }

    [Fact]
    public async Task VersionIsMachineReadable()
    {
        var result = await Run("--version", "--json");
        using var doc = JsonDocument.Parse(result.Out);
        Assert.Equal(0, result.Code);
        Assert.Equal(1, doc.RootElement.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("0.1.0", doc.RootElement.GetProperty("version").GetString());
    }

    [Fact]
    public async Task StatusNeverClaimsLiveEngine()
    {
        var result = await Run("status", "--json");
        using var doc = JsonDocument.Parse(result.Out);
        Assert.Equal(0, result.Code);
        Assert.Equal("offline", doc.RootElement.GetProperty("mode").GetString());
        Assert.Equal("unavailable", doc.RootElement.GetProperty("engineStatus").GetString());
    }

    [Fact]
    public async Task CapabilitiesExplicitlyDenyLiveCapture()
    {
        var result = await Run("capabilities", "--json");
        using var doc = JsonDocument.Parse(result.Out);
        Assert.Equal(0, result.Code);
        var capabilities = doc.RootElement.GetProperty("capabilities").EnumerateArray().ToArray();
        Assert.Single(capabilities.Where(c => c.GetProperty("state").GetString() == "available"));
        Assert.Equal("unavailable", capabilities.Single(c => c.GetProperty("name").GetString() == "capture")
            .GetProperty("state").GetString());
    }

    [Theory]
    [InlineData("capture")]
    [InlineData("status extra")]
    [InlineData("session inspect")]
    [InlineData("session inspect file.txt")]
    [InlineData("status --json --json")]
    public async Task InvalidArgumentsUseStderr(string command)
    {
        var result = await Run(command.Split(' ').Append("--json").ToArray());
        Assert.Equal(2, result.Code);
        Assert.Empty(result.Out);
        using var doc = JsonDocument.Parse(result.Error);
        Assert.Equal("invalid_usage", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task SessionSummaryUsesRealArchiveAndNeverPrintsRows()
    {
        string path = TempFile();
        try
        {
            var snapshot = CarthagoSessionSnapshot.CreateEmpty();
            snapshot.Origin = "SENSITIVE-ORIGIN";
            snapshot.AddRows("Alerts", new[] { new { RuleId = "R001", Detail = "SENSITIVE-ROW" } });
            await new CarthagoSessionArchiveService().SaveAsync(path, snapshot);

            var result = await Run("session", "inspect", path, "--json");
            Assert.Equal(0, result.Code);
            Assert.Empty(result.Error);
            using var doc = JsonDocument.Parse(result.Out);
            Assert.Equal("verified", doc.RootElement.GetProperty("integrity").GetString());
            Assert.Equal("untrusted_import", doc.RootElement.GetProperty("provenance").GetString());
            var categories = doc.RootElement.GetProperty("categories").EnumerateArray().ToArray();
            Assert.Equal(11, categories.Length);
            Assert.Equal(1, categories.Single(c => c.GetProperty("category").GetString() == "Alerts").GetProperty("count").GetInt32());
            Assert.DoesNotContain("SENSITIVE", result.Out);
            Assert.DoesNotContain(path, result.Out);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task TamperedArchiveFailsWithoutSummary()
    {
        string path = TempFile();
        try
        {
            await new CarthagoSessionArchiveService().SaveAsync(path, CarthagoSessionSnapshot.CreateEmpty());
            using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
            {
                zip.GetEntry("data/Alerts.json")!.Delete();
                using var writer = new StreamWriter(zip.CreateEntry("data/Alerts.json").Open());
                writer.Write("[{}]");
            }
            var result = await Run("session", "inspect", path, "--json");
            Assert.Equal(3, result.Code);
            Assert.Empty(result.Out);
            Assert.DoesNotContain(path, result.Error);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task MissingArchiveReturnsDataError()
    {
        var result = await Run("session", "inspect", TempFile(), "--json");
        Assert.Equal(3, result.Code);
        Assert.Empty(result.Out);
    }

    [Fact]
    public async Task CancellationReturns130WithoutOutput()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        using var token = new CancellationTokenSource();
        token.Cancel();
        int code = await CliApplication.RunAsync(new[] { "status", "--json" }, output, error, token.Token);
        Assert.Equal(130, code);
        Assert.Empty(output.ToString());
    }

    private static string TempFile() => Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".csa");

    private static async Task<(int Code, string Out, string Error)> Run(params string[] args)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        int code = await CliApplication.RunAsync(args, output, error);
        return (code, output.ToString(), error.ToString());
    }
}
