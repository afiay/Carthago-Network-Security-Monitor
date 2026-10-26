// SPDX-License-Identifier: MIT
using System;
using System.Text;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Engine.Rules.IotOt;
using Carthago.Engine.Rules.Tuning;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// Separate an observed suspicious request from proof of exploitation.
/// Time proximity, default credentials and metadata protocol mechanics do
/// not by themselves establish unauthorized success or attacker-driven SSRF.
/// </summary>
public sealed class AccuracyCausalityAndProvisioningTests
{
    private static readonly DateTime BaseTime =
        new(2026, 10, 26, 13, 0, 0, DateTimeKind.Utc);

    [Fact]
    public async Task Authorized_Provisioning_Default_Credential_Attempt_Is_Recognized_But_Not_Paged()
    {
        // Same captured bytes as an unauthorized default-pair attempt.
        // Context may establish an approved maintenance window in real
        // deployments, but a free-form note is not trusted approval evidence.
        const string encodedDefault = "YWRtaW46YWRtaW4=";
        var wire = "POST /onvif/device_service HTTP/1.1\r\n"
            + "Host: camera-maintenance.internal\r\n"
            + "Authorization: Basic " + encodedDefault + "\r\n\r\n";
        Assert.True(HttpLight.TryParseHttp(Encoding.ASCII.GetBytes(wire), out var parsed));
        Assert.True(parsed.ObservedDefaultBasicCredential);
        Assert.DoesNotContain(encodedDefault, parsed.JoinedHeaderLines);

        var record = new TrafficRecord
        {
            Source = "192.0.2.81", Destination = "192.0.2.82",
            DestinationPort = 80, Protocol = "TCP", ApplicationProtocol = "HTTP",
            HttpMethod = parsed.Method, HttpHost = parsed.Host,
            HttpUri = parsed.Path, HttpRequestHeaders = parsed.JoinedHeaderLines,
            HttpBasicDefaultCredentialObserved = parsed.ObservedDefaultBasicCredential,
            ProcessName = "approved-device-provisioner.exe",
            Info = "Synthetic maintenance-window provisioning; activity authorized in scenario label only."
        };
        var rule = new R118_DefaultCredentialIoTAttemptRule();
        var result = await rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, BaseTime));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal(0.76, evt.ConfidenceScore, 6);

        foreach (var profile in new[]
            { "Enterprise", "HomeLab", "IoTHeavy", "OTSegment", "Research", "SmallBusiness" })
        {
            var precision = RulePrecisionRuntimeEvaluator.Evaluate(
                rule.Descriptor, evt, record, RuleMode.Alert, profile);
            Assert.False(precision.AllowsAlert);
            Assert.False(precision.ConfidenceSatisfied);
        }
        Assert.DoesNotContain(encodedDefault,
            System.Text.Json.JsonSerializer.Serialize(evt));
    }

    [Theory]
    [InlineData("/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role")]
    [InlineData("/callback?next=%2Flatest%2Fmeta-data%2Fiam%2Fsecurity-credentials")]
    [InlineData("/healthcheck?status=ok")]
    public async Task Time_Adjacent_Inbound_HTTP_And_Metadata_Egress_Do_Not_Prove_Ssrf(
        string inboundUri)
    {
        // This is intentionally NOT a joined trace: shared source/service and
        // temporal adjacency alone do not identify a causal parent request.
        var rule = new R163_SsrfMetadataServiceProbeRule();
        var inbound = new TrafficRecord
        {
            Source = "198.51.100.91", Destination = "10.42.10.11",
            DestinationPort = 8080, Protocol = "TCP",
            ApplicationProtocol = "HTTP", HttpMethod = "GET",
            HttpHost = "service.holdout.internal", HttpUri = inboundUri,
            HttpRequestHeaders = "Host: service.holdout.internal",
            ProcessName = "webapp.exe"
        };
        var inboundResult = await rule.EvaluateAsync(new RuleEvaluationContext(
            inbound, Sensitivity.Balanced, BaseTime));
        Assert.False(inboundResult.Matched);

        var metadata = new TrafficRecord
        {
            Source = "10.42.10.11", Destination = "169.254.169.254",
            DestinationPort = 80, Protocol = "TCP",
            ApplicationProtocol = "HTTP", HttpMethod = "GET",
            HttpHost = "169.254.169.254",
            HttpUri = "/latest/meta-data/iam/security-credentials/holdout-role",
            HttpRequestHeaders = "Host: 169.254.169.254\r\nX-aws-ec2-metadata-token: [REDACTED]",
            ProcessName = "webapp.exe"
        };
        var outboundResult = await rule.EvaluateAsync(new RuleEvaluationContext(
            metadata, Sensitivity.Balanced, BaseTime.AddMilliseconds(20)));
        Assert.True(outboundResult.Matched);
        var evt = Assert.Single(outboundResult.Events);
        Assert.Equal(0.62, evt.ConfidenceScore, 6);

        foreach (var profile in new[]
            { "Enterprise", "HomeLab", "IoTHeavy", "OTSegment", "Research", "SmallBusiness" })
        {
            var precision = RulePrecisionRuntimeEvaluator.Evaluate(
                rule.Descriptor, evt, metadata, RuleMode.Alert, profile);
            Assert.False(precision.AllowsAlert,
                "Unlinked inbound and metadata egress are not proven SSRF.");
            Assert.False(precision.ConfidenceSatisfied);
        }
    }
}
