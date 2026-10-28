// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

/// <summary>Offline MBAP/PDU replay must use capture's OT parser, never packet Info.</summary>
public sealed class ReplayOtParserIntegrationTests
{
    private static readonly string Fixture = ContentPackTestHarness.RepoPath(
        "Tests", "RuleReplaySamples", "malicious", "modbus-write-function.json");

    private static async Task<TuningBenchmarkSampleResult> RunOneAsync(string json)
    {
        var folder = Path.Combine(Path.GetTempPath(), "carthago-ot-replay-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(folder, "sample.json"), json);
            var report = await new TuningBenchmarkRunner().RunAsync(new TuningBenchmarkOptions
            {
                ReplayDirectory = folder
            });
            return Assert.Single(report.SampleResults);
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    public async Task MBAP_Write_Bytes_Produce_R240_Positive_Recognition()
    {
        var result = await RunOneAsync(await File.ReadAllTextAsync(Fixture));
        Assert.Contains("R240", result.ExpectedMatches);
        Assert.Contains("R240", result.ActualMatches);
        Assert.Empty(result.MissingExpectedMatches);
        Assert.Empty(result.Errors);
        Assert.True(result.MaximumConfidence >= 0.65);
    }

    [Fact]
    public async Task Read_Function_Is_Not_A_Write_Even_When_Info_Claims_Write()
    {
        var json = await File.ReadAllTextAsync(Fixture);
        json = json.Replace("000100000006010600000001", "000100000006010300000001", StringComparison.Ordinal);
        json = json.Replace("\"expectedMatches\": [\"R240\"]",
            "\"expectedMatches\": [], \"expectedNonMatches\": [\"R240\"]", StringComparison.Ordinal);
        json = json.Replace("\"expectedMinimumConfidence\": 0.65",
            "\"expectedMinimumConfidence\": 0.0", StringComparison.Ordinal);
        var result = await RunOneAsync(json);
        Assert.DoesNotContain("R240", result.ActualMatches);
        Assert.Empty(result.UnexpectedMatches);
    }

    [Fact]
    public async Task Conflicting_Claimed_Protocol_Is_Rejected_By_Replay_Loader()
    {
        var json = await File.ReadAllTextAsync(Fixture);
        json = json.Replace("000100000006010600000001", "000100000006010300000001", StringComparison.Ordinal);
        json = json.Replace("\"sourcePort\": 51000,", "\"sourcePort\": 51000, \"applicationProtocol\": \"modbus.write\",", StringComparison.Ordinal);
        var failure = await Assert.ThrowsAsync<InvalidDataException>(
            () => RunOneAsync(json));
        Assert.Contains("protocol conflict", failure.Message, StringComparison.OrdinalIgnoreCase);
    }
    [Fact]
    public async Task Port_502_And_Info_Without_Payload_Do_Not_Prove_Modbus_Write()
    {
        // Edit JSON structurally: exact newline-based replacements silently
        // failed on Windows CRLF checkouts and left the original Modbus
        // PDU in place, creating a false failure of this negative control.
        var document = JsonNode.Parse(await File.ReadAllTextAsync(Fixture))!.AsObject();
        Assert.True(document.Remove("rawOtTcpPayloadsByRecordIndex"),
            "The fixture must contain a raw OT payload for this negative test.");
        document["expectedMatches"] = new JsonArray();
        document["expectedNonMatches"] = new JsonArray("R240");
        document["expectedMinimumConfidence"] = 0.0;

        Assert.False(document.ContainsKey("rawOtTcpPayloadsByRecordIndex"));
        var result = await RunOneAsync(document.ToJsonString());
        Assert.DoesNotContain("R240", result.ActualMatches);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public async Task Modbus_Write_Response_Does_Not_Impersonate_Client_Request()
    {
        var json = await File.ReadAllTextAsync(Fixture);
        json = json.Replace("\"sourcePort\": 51000", "\"sourcePort\": 502", StringComparison.Ordinal);
        json = json.Replace("\"destinationPort\": 502", "\"destinationPort\": 51000", StringComparison.Ordinal);
        json = json.Replace("\"expectedMatches\": [\"R240\"]",
            "\"expectedMatches\": [], \"expectedNonMatches\": [\"R240\"]", StringComparison.Ordinal);
        json = json.Replace("\"expectedMinimumConfidence\": 0.65",
            "\"expectedMinimumConfidence\": 0.0", StringComparison.Ordinal);
        var result = await RunOneAsync(json);
        Assert.DoesNotContain("R240", result.ActualMatches);
    }

    [Fact]
    public async Task Malformed_Mbap_Protocol_Id_Is_Rejected()
    {
        var json = await File.ReadAllTextAsync(Fixture);
        json = json.Replace("000100000006010600000001", "000101000006010600000001", StringComparison.Ordinal);
        var failure = await Assert.ThrowsAsync<InvalidDataException>(() => RunOneAsync(json));
        Assert.Contains("OT parser rejected", failure.Message, StringComparison.Ordinal);
    }

}
