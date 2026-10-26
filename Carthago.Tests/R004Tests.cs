// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

[Collection("Legacy rules R001-R005 isolated")]
public sealed class R004Tests : IDisposable
{
    private static readonly DateTime T0 = new(2026, 10, 26, 14, 0, 0, DateTimeKind.Utc);
    private readonly R004_BruteForceRule _rule = new();
    public R004Tests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Packet(
        string src = "10.244.0.10", string dst = "10.244.1.10",
        int port = 22, string? info = "Failed password for invalid user admin")
        => new()
        {
            Source = src, Destination = dst, SourcePort = 55000,
            DestinationPort = port, Protocol = "TCP", ApplicationService = "SSH",
            Flags = "PSH,ACK", Info = info, Length = 200
        };

    private async Task<RuleEvaluationResult> Evaluate(TrafficRecord record, int seconds)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, T0.AddSeconds(seconds)));

    [Fact]
    public async Task Configured_Number_Of_Explicit_Failed_Logins_Produces_One_Brute_Force_Event()
    {
        RuleEvaluationResult? result = null;
        for (var i = 0; i < 30; i++)
        {
            var evaluated = await Evaluate(Packet(), i);
            if (i < 4) Assert.False(evaluated.Matched);
            if (!evaluated.Matched || evaluated.Events.Count == 0) continue;
            result = evaluated;
            break;
        }
        Assert.NotNull(result);
        var evt = Assert.Single(result!.Events);
        Assert.Equal("R004", evt.RuleId);
        Assert.InRange(evt.Count, 5, 30);
        Assert.Equal("10.244.0.10", evt.SourceIp);
        Assert.Equal("10.244.1.10", evt.DestinationIp);
        Assert.Equal(22, evt.DestinationPort);
        Assert.DoesNotContain("password for invalid user admin",
            evt.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Handshakes_And_Ssh_Banners_Are_Not_Authentication_Failures()
    {
        for (var i = 0; i < 30; i++)
        {
            var record = Packet(info: i % 2 == 0 ? null : "SSH-2.0-OpenSSH_9.5");
            record.Flags = i % 2 == 0 ? "SYN" : "ACK";
            Assert.False((await Evaluate(record, i)).Matched);
        }
        Assert.False((await Evaluate(Packet(info: "Authentication succeeded"), 31)).Matched);
    }

    [Fact]
    public async Task Successful_And_Ordinary_Ftp_Commands_Do_Not_Fabricate_Failure_Counts()
    {
        for (var i = 0; i < 20; i++)
        {
            var record = Packet(port: 21, info: i % 2 == 0 ? "USER admin" : "PASS [REDACTED]");
            record.ApplicationService = "FTP";
            Assert.False((await Evaluate(record, i)).Matched);
        }
    }

    [Fact]
    public async Task Different_Source_And_Target_Triples_Do_Not_Combine_Credential_Failures()
    {
        for (var i = 0; i < 4; i++)
        {
            Assert.False((await Evaluate(Packet(src: "10.244.0.11", dst: "10.244.1.11"), i)).Matched);
            Assert.False((await Evaluate(Packet(src: "10.244.0.11", dst: "10.244.1.12"), i)).Matched);
            Assert.False((await Evaluate(Packet(src: "10.244.0.12", dst: "10.244.1.11"), i)).Matched);
        }
        RuleEvaluationResult? detected = null;
        for (var i = 4; i < 30; i++)
        {
            var current = await Evaluate(
                Packet(src: "10.244.0.11", dst: "10.244.1.11"), i + 2);
            if (!current.Matched || current.Events.Count == 0) continue;
            detected = current;
            break;
        }
        Assert.NotNull(detected);
        Assert.InRange(Assert.Single(detected!.Events).Count, 5, 30);
    }

    [Fact]
    public async Task Expired_Attempts_And_Clock_Jumps_Do_Not_Complete_A_Brute_Force_Window()
    {
        for (var i = 0; i < 4; i++)
            Assert.False((await Evaluate(Packet(src: "10.244.0.13"), i)).Matched);

        // Only one fresh failed login at +120s; four old attempts expired.
        Assert.False((await Evaluate(Packet(src: "10.244.0.13"), 120)).Matched);
        Assert.False((await Evaluate(Packet(src: "10.244.0.13"), 1)).Matched);
    }

    [Fact]
    public async Task Failure_Words_Without_A_Real_Authentication_Protocol_Are_Not_Enough()
    {
        for (var i = 0; i < 20; i++)
        {
            var record = Packet(port: 8080, info: "failed password");
            record.ApplicationService = "HTTP";
            Assert.False((await Evaluate(record, i)).Matched);
        }
    }
}
