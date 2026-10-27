// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>R012: certificate evidence rather than arbitrary Info strings.</summary>
[Collection("Legacy rules R011-R015 isolated")]
public sealed class R012AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R012_SuspiciousTlsRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 4, 0, 0, DateTimeKind.Utc);
    public R012AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Tls(string destination = "93.184.216.34")
        => new() { Source = "10.12.0.1", Destination = destination,
            Protocol = "TCP", DestinationPort = 443, Length = 500,
            TlsVersion = "TLS 1.3", CertIssuer = "CN=Trusted Issuer",
            CertSubject = "CN=private-host" };

    private async Task<RuleEvaluationResult> See(TrafficRecord r, int second = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(second)));

    [Fact]
    public async Task Expired_Structured_Certificate_Produces_A_Review_Candidate()
    {
        var record = Tls(); record.CertValidTo = T0.AddDays(-1);
        var evt = Assert.Single((await See(record)).Events);
        Assert.Equal("R012", evt.RuleId);
        Assert.Equal(SeverityLevel.Medium, evt.Severity);
        Assert.Contains("expired", evt.Description);
        Assert.DoesNotContain("private-host", evt.Description);
    }

    [Fact]
    public async Task Not_Yet_Valid_Structured_Certificate_Produces_A_Review_Candidate()
    {
        var record = Tls(); record.CertValidFrom = T0.AddDays(1);
        var evt = Assert.Single((await See(record)).Events);
        Assert.Contains("not yet valid", evt.Description);
    }

    [Fact]
    public async Task Self_Issued_Structured_Certificate_Is_A_Candidate_Not_A_Confirmed_Attack()
    {
        var record = Tls(); record.CertIssuer = record.CertSubject;
        var evt = Assert.Single((await See(record)).Events);
        Assert.Contains("self-issued", evt.Description);
        Assert.Contains("require validation", evt.Description);
    }

    [Fact]
    public async Task Untrusted_Info_Flags_Alone_Are_Not_Certificate_Observations()
    {
        foreach (var marker in new[] { "ExpiredCert", "InvalidCert", "SelfSigned" })
        {
            var record = Tls(); record.Info = "Documentation: " + marker;
            Assert.False((await See(record)).Matched);
        }
    }

    [Fact]
    public async Task Contradictory_Info_Cannot_Override_Valid_Certificate_Dates()
    {
        var record = Tls();
        record.Info = "ExpiredCert InvalidCert SelfSigned";
        record.CertValidFrom = T0.AddDays(-7);
        record.CertValidTo = T0.AddDays(30);
        Assert.False((await See(record)).Matched);
    }

    [Fact]
    public async Task Wrong_Transport_Port_Or_Missing_Attribution_Does_Not_Produce_Event()
    {
        var udp = Tls(); udp.Protocol = "UDP"; udp.CertValidTo = T0.AddDays(-1);
        var alternatePort = Tls(); alternatePort.DestinationPort = 8443; alternatePort.CertValidTo = T0.AddDays(-1);
        var noSource = Tls(); noSource.Source = null; noSource.CertValidTo = T0.AddDays(-1);
        var noDest = Tls(); noDest.Destination = null; noDest.CertValidTo = T0.AddDays(-1);
        foreach (var record in new[] { udp, alternatePort, noSource, noDest })
            Assert.False((await See(record)).Matched);
    }

    [Fact]
    public async Task Uncorroborated_InvalidCert_Marker_Does_Not_Override_Complete_Valid_Metadata()
    {
        var record = Tls();
        record.CertValidFrom = T0.AddDays(-10);
        record.CertValidTo = T0.AddDays(10);
        record.Info = "InvalidCert";
        Assert.False((await See(record)).Matched);
    }

    [Fact]
    public async Task Repeated_Flow_Is_Suppressed_But_Independent_Destination_Is_Not()
    {
        var first = Tls(); first.CertValidTo = T0.AddDays(-1);
        Assert.True((await See(first)).Matched);
        var repeated = await See(first, 1);
        Assert.True(repeated.Suppressed);
        Assert.Empty(repeated.Events);
        var second = Tls("93.184.216.35"); second.CertValidTo = T0.AddDays(-1);
        Assert.Equal("93.184.216.35", Assert.Single((await See(second, 1)).Events).DestinationIp);
    }
}
