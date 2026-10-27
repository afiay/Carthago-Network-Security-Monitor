// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;
namespace Carthago.Tests;

[Collection("Legacy rules R011-R015 isolated")]
public sealed class R025AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R025_TlsCertificateExpiredOrExpiringSoonRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 0, 0, 0, DateTimeKind.Utc);
    public R025AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord record, int second = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(record, Sensitivity.Balanced, T0.AddSeconds(second)));

    private static TrafficRecord Cert(DateTime? validTo = null, string dst = "8.8.8.8")
        => new() { Protocol = "TLS", TlsVersion = "TLS1.3", Source = "10.25.0.2",
            Destination = dst, DestinationPort = 443, Length = 140,
            CertValidFrom = T0.AddDays(-100), CertValidTo = validTo ?? T0.AddDays(-1) };


    [Fact] public async Task Expired_Certificate_Produces_High_Severity_Attributed_Observation()
    {
        var evt = Assert.Single((await See(Cert())).Events);
        Assert.Equal("R025", evt.RuleId);
        Assert.Equal(SeverityLevel.High, evt.Severity);
        Assert.Equal(1, evt.Count);
        Assert.Equal("8.8.8.8", evt.DestinationIp);
    }
    [Fact] public async Task Seven_Day_Boundary_Produces_Medium_But_Later_Expiry_Does_Not()
    {
        Assert.False((await See(Cert(T0.AddDays(8)))).Matched);
        var evt = Assert.Single((await See(Cert(T0.AddDays(7)), 1)).Events);
        Assert.Equal(SeverityLevel.Medium, evt.Severity);
        Assert.InRange(evt.Count, 6, 7);
    }
    [Fact] public async Task Inconsistent_Validity_And_Missing_Certificate_Are_Rejected()
    {
        var invalid = Cert(); invalid.CertValidFrom = T0.AddDays(2);
        var absent = Cert(); absent.CertValidTo = null;
        Assert.False((await See(invalid)).Matched);
        Assert.False((await See(absent)).Matched);
    }
    [Fact] public async Task Port_Only_Tcp_And_Quic_Do_Not_Manufacture_Certificate_Evidence()
    {
        var tcp = Cert(); tcp.Protocol = "TCP"; tcp.TlsVersion = null;
        var quic = Cert(); quic.IsQuic = true;
        var otherPort = Cert(); otherPort.DestinationPort = 8443;
        foreach (var r in new[] { tcp, quic, otherPort }) Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Malformed_Endpoints_And_Zero_Length_Are_Rejected()
    {
        var badSource = Cert(); badSource.Source = "not-ip";
        var badDest = Cert(); badDest.Destination = "not-ip";
        var empty = Cert(); empty.Length = 0;
        foreach (var r in new[] { badSource, badDest, empty }) Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Cooldown_Suppresses_Duplicate_But_Not_Another_Server()
    {
        Assert.True((await See(Cert(), 0)).Matched);
        var suppressed = await See(Cert(), 1);
        Assert.True(suppressed.Suppressed);
        Assert.Empty(suppressed.Events);
        var other = Assert.Single((await See(Cert(dst: "9.9.9.9"), 1)).Events);
        Assert.Equal("9.9.9.9", other.DestinationIp);
        Assert.DoesNotContain("CertSubject", other.Description);
    }

}
