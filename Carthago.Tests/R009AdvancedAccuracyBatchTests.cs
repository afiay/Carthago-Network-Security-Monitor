// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>R009: observed VPN/proxy classification without intent inflation.</summary>
[Collection("Legacy rules R006-R010 isolated")]
public sealed class R009AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R009_VpnProxyRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 4, 0, 0, DateTimeKind.Utc);
    public R009AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Flow(string source = "10.209.0.1",
        string? destination = "1.1.1.1", int? port = 443,
        string? protocol = "TCP", bool? vpn = null, bool? proxy = null)
        => new() { Source = source, Destination = destination, DestinationPort = port,
            Protocol = protocol, IsVpn = vpn, IsProxy = proxy, Length = 250 };

    private async Task<RuleEvaluationResult> See(TrafficRecord record, int second = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, T0.AddSeconds(second)));

    [Fact]
    public async Task Observed_Vpn_Classification_Produces_Attributed_Usage_Candidate()
    {
        var evt = Assert.Single((await See(Flow(vpn: true))).Events);
        Assert.Equal("R009", evt.RuleId);
        Assert.Equal("10.209.0.1", evt.SourceIp);
        Assert.Equal("1.1.1.1", evt.DestinationIp);
        Assert.Equal(443, evt.DestinationPort);
        Assert.Contains("authorization not determined", evt.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Observed_Proxy_Classification_Works_Without_Vpn_Flag()
    {
        var evt = Assert.Single((await See(Flow(proxy: true))).Events);
        Assert.Equal("R009", evt.RuleId);
        Assert.Equal(SeverityLevel.Medium, evt.Severity);
    }

    [Fact]
    public async Task Explicit_Negatives_And_Unknown_Classifications_Are_Not_Matches()
    {
        foreach (var record in new[]
        {
            Flow(vpn: false, proxy: false),
            Flow(vpn: null, proxy: null),
            Flow(vpn: false, proxy: null),
            Flow(vpn: null, proxy: false)
        })
            Assert.False((await See(record)).Matched);
    }

    [Fact]
    public async Task Log_Text_And_Port_Numbers_Alone_Cannot_Impersonate_Classification()
    {
        var record = Flow(port: 51820);
        record.Info = "VPN detected proxy enabled through tunnel";
        record.ApplicationService = "WIREGUARD";
        Assert.False((await See(record)).Matched);
    }

    [Fact]
    public async Task Missing_Attribution_Or_Transport_Cannot_Create_An_Event()
    {
        var noSource = Flow(vpn: true); noSource.Source = null;
        var noDest = Flow(vpn: true, destination: null);
        var noProtocol = Flow(vpn: true, protocol: null);
        var unsupported = Flow(vpn: true, protocol: "ARP");
        foreach (var record in new[] { noSource, noDest, noProtocol, unsupported })
            Assert.False((await See(record)).Matched);
    }

    [Fact]
    public async Task Missing_And_Out_Of_Range_Ports_Are_Not_Network_Flow_Evidence()
    {
        foreach (int? port in new int?[] { null, 0, -1, 65536 })
            Assert.False((await See(Flow(port: port, proxy: true))).Matched);
        Assert.True((await See(Flow(port: 51820, protocol: "UDP", vpn: true))).Matched);
    }

    [Fact]
    public async Task Repeated_Classification_Is_Debounced_But_Different_Source_Is_Independent()
    {
        Assert.True((await See(Flow(vpn: true))).Matched);
        var repeated = await See(Flow(vpn: true), 1);
        Assert.Empty(repeated.Events);
        Assert.True(repeated.Suppressed);
        var other = await See(Flow(source: "10.209.0.2", vpn: true), 1);
        Assert.Equal("10.209.0.2", Assert.Single(other.Events).SourceIp);
    }

    [Fact]
    public async Task Proxy_True_And_Vpn_False_Still_Represent_One_Observed_Proxy_Flow()
    {
        var evt = Assert.Single((await See(Flow(vpn: false, proxy: true))).Events);
        Assert.Equal(1, evt.Count);
        Assert.Equal("R009", evt.RuleId);
    }
}
