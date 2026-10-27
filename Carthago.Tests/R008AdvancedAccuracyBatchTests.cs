// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>R008: bounded egress byte evidence, overflow and attribution.</summary>
[Collection("Legacy rules R006-R010 isolated")]
public sealed class R008AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R008_ExfiltrationRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 3, 0, 0, DateTimeKind.Utc);
    public R008AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Flow(string source = "10.208.0.1",
        string? destination = "8.8.4.4", int length = 1_000_000,
        string? protocol = "TCP")
        => new() { Source = source, Destination = destination, DestinationPort = 443,
            Protocol = protocol, Length = length };

    private async Task<RuleEvaluationResult> See(TrafficRecord record, int second)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, T0.AddSeconds(second)));

    [Fact]
    public async Task Five_Million_Configured_Bytes_Produce_Attributed_High_Volume_Candidate()
    {
        for (int i = 0; i < 4; i++)
            Assert.False((await See(Flow(), i)).Matched);
        var hit = await See(Flow(), 4);
        var evt = Assert.Single(hit.Events);
        Assert.Equal("R008", evt.RuleId);
        Assert.Equal(5_000_000, evt.Count);
        Assert.Equal("10.208.0.1", evt.SourceIp);
        Assert.Equal("8.8.4.4", evt.DestinationIp);
        Assert.Contains("unconfirmed", evt.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Four_Million_Bytes_Are_Below_Configured_Threshold()
    {
        for (int i = 0; i < 4; i++)
            Assert.False((await See(Flow(), i)).Matched);
    }

    [Fact]
    public async Task Internal_And_Documentation_Addresses_Cannot_Contribute_To_Internet_Egress()
    {
        foreach (var destination in new[] { "10.20.30.40", "192.168.0.1", "198.51.100.12", "127.0.0.1" })
            Assert.False((await See(Flow(destination: destination, length: 4_000_000), 0)).Matched);
        for (int i = 0; i < 4; i++)
            Assert.False((await See(Flow(), i + 1)).Matched);
        Assert.True((await See(Flow(), 5)).Matched);
    }

    [Fact]
    public async Task Missing_Endpoint_Unsupported_Transport_And_Invalid_Length_Do_Not_Prime_Bytes()
    {
        var noDestination = Flow(destination: null, length: 4_000_000);
        var noSource = Flow(length: 4_000_000); noSource.Source = null;
        var badProtocol = Flow(length: 4_000_000, protocol: "ARP");
        var zero = Flow(length: 0);
        var negative = Flow(length: -1);
        var noPort = Flow(length: 4_000_000); noPort.DestinationPort = null;
        var invalidPort = Flow(length: 4_000_000); invalidPort.DestinationPort = -1;
        foreach (var record in new[] { noDestination, noSource, badProtocol, zero, negative, noPort, invalidPort })
            Assert.False((await See(record, 0)).Matched);
        for (int i = 0; i < 4; i++)
            Assert.False((await See(Flow(), i + 1)).Matched);
        Assert.Equal(5_000_000, Assert.Single((await See(Flow(), 5)).Events).Count);
    }

    [Fact]
    public async Task Future_Dated_Egress_Does_Not_Inflate_Current_Byte_Window()
    {
        Assert.False((await See(Flow(length: 4_000_000), 1000)).Matched);
        for (int i = 0; i < 4; i++)
            Assert.False((await See(Flow(), i)).Matched);
        Assert.Equal(5_000_000, Assert.Single((await See(Flow(), 4)).Events).Count);
    }

    [Fact]
    public async Task Expired_Bytes_Cannot_Complete_The_Next_Window()
    {
        Assert.False((await See(Flow(length: 4_000_000), 0)).Matched);
        Assert.False((await See(Flow(), 61)).Matched);
        for (int i = 1; i < 4; i++)
            Assert.False((await See(Flow(), 61 + i)).Matched);
        Assert.Equal(5_000_000, Assert.Single((await See(Flow(), 65)).Events).Count);
    }

    [Fact]
    public async Task Sources_Are_Independent_When_Bytes_Are_Interleaved()
    {
        for (int i = 0; i < 4; i++)
        {
            Assert.False((await See(Flow(source: "10.208.0.11"), i)).Matched);
            Assert.False((await See(Flow(source: "10.208.0.12"), i)).Matched);
        }
        var hit = await See(Flow(source: "10.208.0.11"), 4);
        Assert.Equal("10.208.0.11", Assert.Single(hit.Events).SourceIp);
        Assert.False((await See(Flow(source: "10.208.0.12", length: 100), 4)).Matched);
    }

    [Fact]
    public async Task Int32_Maximum_Packet_Length_Does_Not_Overflow_Byte_Accounting()
    {
        var hit = await See(Flow(length: int.MaxValue), 0);
        var evt = Assert.Single(hit.Events);
        Assert.Equal(int.MaxValue, evt.Count);
        Assert.Contains("2147483647", evt.Description, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Authorized_Backup_Like_Volume_Is_Not_Claimed_To_Be_Confirmed_Theft()
    {
        for (int i = 0; i < 4; i++)
        {
            var backup = Flow();
            backup.ProcessName = "approved-backup.exe";
            Assert.False((await See(backup, i)).Matched);
        }
        var last = Flow(); last.ProcessName = "approved-backup.exe";
        var evt = Assert.Single((await See(last, 4)).Events);
        Assert.Contains("unconfirmed", evt.Description, StringComparison.OrdinalIgnoreCase);
        // This legacy rule cannot determine authorization from process name.
        // It remains a volume candidate, not a labeled malicious true positive.
    }
}
