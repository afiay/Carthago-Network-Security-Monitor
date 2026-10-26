// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>R004 batch gate: five advanced failure-attribution/correlation cases.</summary>
[Collection("Legacy rules R001-R005 isolated")]
public sealed class R004AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R004_BruteForceRule _rule = new();
    private static readonly DateTime Origin = new(2026, 10, 26, 14, 0, 0, DateTimeKind.Utc);
    public R004AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Login(string? outcome = "Failed password for invalid user guest",
        int port = 22, string service = "SSH", string source = "10.254.1.1",
        string dest = "10.254.2.1", string protocol = "TCP")
        => new() { Source = source, Destination = dest, DestinationPort = port,
            SourcePort = 55000, Protocol = protocol, ApplicationService = service,
            Flags = "PSH,ACK", Info = outcome, Length = 200 };

    private async Task<RuleEvaluationResult> See(TrafficRecord record, int second)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, Origin.AddSeconds(second)));

    [Fact]
    public async Task Multiple_Structured_Failure_Phrases_Corroborate_One_Source_Target_Service()
    {
        var outcomes = new[] {
            "Failed password for invalid user guest",
            "Authentication failed for user guest",
            "Login failed from external client",
            "Invalid credentials supplied to SSH service",
            "Login incorrect for user guest"
        };
        for (var i = 0; i < 4; i++)
            Assert.False((await See(Login(outcomes[i]), i)).Matched);
        var result = await See(Login(outcomes[4]), 4);
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal(5, evt.Count);
        Assert.DoesNotContain("guest", evt.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Many_Successes_Interleaved_With_Four_Failures_Do_Not_Reach_Threshold()
    {
        for (var i = 0; i < 4; i++)
        {
            Assert.False((await See(Login(), i * 2)).Matched);
            Assert.False((await See(Login("Accepted publickey for service account"), i * 2 + 1)).Matched);
        }
        Assert.True((await See(Login("Authentication failure"), 9)).Matched);
    }

    [Fact]
    public async Task Ssh_And_Rdp_Are_Independent_Target_Service_Windows()
    {
        for (var i = 0; i < 4; i++)
        {
            Assert.False((await See(Login(port: 22, service: "SSH"), i)).Matched);
            Assert.False((await See(Login(port: 3389, service: "RDP"), i)).Matched);
        }
        var detected = await See(Login(port: 22, service: "SSH"), 5);
        Assert.True(detected.Matched);
        Assert.Equal(22, Assert.Single(detected.Events).DestinationPort);
    }

    [Fact]
    public async Task Out_Of_Order_Future_Login_Does_Not_Create_False_Brute_Force_Count()
    {
        Assert.False((await See(Login(), 500)).Matched);
        for (var i = 0; i < 4; i++)
            Assert.False((await See(Login(), i)).Matched);
        var current = await See(Login(), 5);
        Assert.True(current.Matched);
        Assert.Equal(5, Assert.Single(current.Events).Count);
    }

    [Fact]
    public async Task Udp_And_Unrecognized_Service_Logs_Cannot_Fabricate_Auth_Failures()
    {
        for (var i = 0; i < 8; i++)
        {
            Assert.False((await See(Login(protocol: "UDP"), i)).Matched);
            Assert.False((await See(Login(port: 8080, service: "HTTPS"), i)).Matched);
        }
        for (var i = 0; i < 4; i++)
            Assert.False((await See(Login(), i + 10)).Matched);
        Assert.True((await See(Login(), 15)).Matched);
    }
}
