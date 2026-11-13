// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Carthago.Engine;
using Carthago.Services.Sensors;
using Xunit;

namespace Carthago.Tests;

// Explicit finding-level matrix, not an estimate of real-world precision/recall.
public sealed class ActiveFindingReleaseMatrixTests
{
    private static readonly Guid Adapter = Guid.Parse("02702701-1234-4321-9999-000000000001");
    private static readonly IPAddress Source = IPAddress.Parse("192.168.1.20"), Target = IPAddress.Parse("192.168.1.1");
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);
    private static ActiveEvidenceRow Row(int rule, string variant, DateTimeOffset t, bool crossesExpiry = true)
    {
        bool changed = variant == "changed", ambiguous = variant == "ambiguous";
        switch (rule)
        {
            case 1: case 2:
                var before = rule == 1 ? TcpExposureStatus.Refused : TcpExposureStatus.Open;
                var after = rule == 1 ? TcpExposureStatus.Open : TcpExposureStatus.Refused;
                return ActiveEvidenceProjection.From(Adapter, TcpExposureSensor.DefaultPorts.Select(p =>
                    new TcpExposureObservation(Source, Target, p, p == 443 ?
                        (ambiguous ? TcpExposureStatus.TimedOut : changed ? after : before) :
                        TcpExposureStatus.Refused, t, TimeSpan.Zero, null)).ToArray());
            case 3:
                return ActiveEvidenceProjection.From(Adapter, new DnsIntegrityObservation(Source, Target, "lab.example",
                    ambiguous ? DnsIntegrityStatus.TimedOut : DnsIntegrityStatus.AnswersObserved,
                    ambiguous ? Array.Empty<string>() : new[] { changed ? "192.0.2.2" : "192.0.2.1" }, 0, t, TimeSpan.Zero, null));
            case 4: case 5: case 6:
                bool expired = rule == 5 && changed;
                var policy = expired ? SslPolicyErrors.RemoteCertificateChainErrors :
                    rule == 6 && changed ? SslPolicyErrors.RemoteCertificateNameMismatch : SslPolicyErrors.None;
                return ActiveEvidenceProjection.From(Adapter, new TlsInspectionObservation(Source, Target, 443, "lab.example",
                    ambiguous ? TlsInspectionStatus.HandshakeFailed :
                        policy == SslPolicyErrors.None ? TlsInspectionStatus.Authenticated : TlsInspectionStatus.CertificateRejected,
                    ambiguous ? null : new TlsCertificateEvidence("subject", "issuer", "serial",
                        new string(rule == 4 && changed ? 'b' : 'a', 64), Now.AddDays(-2),
                        rule == 5 && crossesExpiry ? Now.AddMinutes(-7) : Now.AddDays(2),
                        expired ? "Expired" : "WithinValidityPeriod", null, null, policy,
                        expired ? new[] { X509ChainStatusFlags.NotTimeValid } : Array.Empty<X509ChainStatusFlags>(), null), null, null, t, TimeSpan.Zero));
            case 7: case 8:
                var headers = rule == 8 && changed ? Array.Empty<HttpHeaderEvidence>() :
                    new[] { new HttpHeaderEvidence("Strict-Transport-Security", new[] { "max-age=123" }) };
                return ActiveEvidenceProjection.From(Adapter, new HttpHealthObservation(Source, Target, 443, "lab.example", true,
                    ambiguous ? HttpHealthStatus.TimedOut : HttpHealthStatus.ResponseObserved,
                    ambiguous ? null : rule == 7 && changed ? 503 : 200,
                    ambiguous ? Array.Empty<HttpHeaderEvidence>() : headers, HttpRedirectScope.NotRedirect, null, t, TimeSpan.Zero));
            case 9: case 10:
                const string a = "02:00:00:00:00:01", b = "02:00:00:00:00:02";
                return ActiveEvidenceProjection.From(Adapter, new GatewayIntegrityObservation(Source, Target,
                    ambiguous ? GatewayIntegrityStatus.NoReply : rule == 10 && changed ? GatewayIntegrityStatus.ConflictingClaims : GatewayIntegrityStatus.Observed,
                    ambiguous ? Array.Empty<string>() : changed ? (rule == 10 ? new[] { a, b } : new[] { b }) : new[] { a },
                    null, false, null, false, t));
            case 11:
                return ActiveEvidenceProjection.From(Adapter, new SnmpInfrastructureObservation(Source, Target,
                    ambiguous ? SnmpInfrastructureStatus.Partial : SnmpInfrastructureStatus.Observed,
                    new SnmpInfrastructureEvidence("desc", "1.3.6.1.4.1.9", changed ? 2u : 1u, "name",
                        ambiguous ? null : changed ? 48 : 24), t, TimeSpan.Zero));
            default: throw new ArgumentOutOfRangeException(nameof(rule));
        }
    }

    [Theory]
    [InlineData(1, "positive")] [InlineData(1, "benign")] [InlineData(1, "ambiguous")]
    [InlineData(2, "positive")] [InlineData(2, "benign")] [InlineData(2, "ambiguous")]
    [InlineData(3, "positive")] [InlineData(3, "benign")] [InlineData(3, "ambiguous")]
    [InlineData(4, "positive")] [InlineData(4, "benign")] [InlineData(4, "ambiguous")]
    [InlineData(5, "positive")] [InlineData(5, "benign")] [InlineData(5, "ambiguous")]
    [InlineData(6, "positive")] [InlineData(6, "benign")] [InlineData(6, "ambiguous")]
    [InlineData(7, "positive")] [InlineData(7, "benign")] [InlineData(7, "ambiguous")]
    [InlineData(8, "positive")] [InlineData(8, "benign")] [InlineData(8, "ambiguous")]
    [InlineData(9, "positive")] [InlineData(9, "benign")] [InlineData(9, "ambiguous")]
    [InlineData(10, "positive")] [InlineData(10, "benign")] [InlineData(10, "ambiguous")]
    [InlineData(11, "positive")] [InlineData(11, "benign")] [InlineData(11, "ambiguous")]
    public void EveryRuleRequiresTwoMatchingDefiniteChanges(int rule, string scenario)
    {
        bool crossesExpiry = scenario != "benign";
        var baseline = Row(rule, "baseline", Now.AddHours(-1), crossesExpiry);
        var first = Row(rule, scenario == "benign" ? "baseline" : "changed", Now.AddMinutes(-5), crossesExpiry);
        var current = Row(rule, scenario == "positive" ? "changed" : scenario == "ambiguous" ? "ambiguous" : "baseline", Now, crossesExpiry);
        var findings = ActiveFindingQualification.Qualify(baseline, first, current, Now.AddMinutes(-10).UtcDateTime.Ticks, Now);
        if (scenario == "positive")
        {
            // Real certificate expiry also changes the strict TLS trust policy.
            // Preserve both findings; do not suppress the second valid change.
            if (rule == 5)
                Assert.Equal(new[] { "ASD005", "ASD006" }, findings.Select(x => x.RuleId).OrderBy(x => x).ToArray());
            else Assert.Single(findings);
            var finding = Assert.Single(findings.Where(x => x.RuleId == $"ASD{rule:000}"));
            Assert.Equal(baseline.Id, finding.BaselineId);
            Assert.Equal(first.Id, finding.FirstObservationId);
            Assert.Equal(current.Id, finding.ConfirmingObservationId);
            var evt = ActiveFindingQualification.ToDetection(finding);
            Assert.Equal(finding.RuleId, evt.RuleId);
            Assert.Equal(finding.Id, evt.EventId);
            Assert.Null(evt.PacketId); Assert.Null(evt.FlowId);
        }
        else Assert.Empty(findings);
    }

    [Fact]
    public void DuplicateJsonCannotQualifyEvenWithoutStoreBoundary()
    {
        var baseline = Row(3, "baseline", Now.AddHours(-1));
        var first = Row(3, "changed", Now.AddMinutes(-5));
        var current = Row(3, "changed", Now);
        current.EvidenceJson = "{\"Addresses\":[\"192.0.2.1\"],\"Addresses\":[\"192.0.2.2\"],\"ResponseCode\":0}";
        Assert.Equal("Incomparable", ActiveChangeDetector.Compare(baseline, current).Status);
        Assert.Empty(ActiveFindingQualification.Qualify(baseline, first, current, Now.AddMinutes(-10).UtcDateTime.Ticks, Now));
    }
}
