// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Engine.Rules.IotOt;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// Deterministic, table-driven accuracy controls. The matrix varies actual
/// wire-authentication and cloud-metadata predicates, not only descriptions
/// or severity labels. Cases are synthetic and must not be interpreted as
/// independent real-world field prevalence.
/// </summary>
public sealed class AccuracyScenarioMatrixTests
{
    private static readonly DateTime ReplayTime =
        new(2026, 10, 26, 12, 0, 0, DateTimeKind.Utc);

    private static RuleEvaluationContext Context(TrafficRecord record)
        => new(record, Sensitivity.Balanced, ReplayTime);

    public static IEnumerable<object[]> ValidDefaultBasicScenarios()
    {
        string[] hosts =
        {
            "camera-lab.internal", "nvr-lab.internal",
            "router02.lab.internal", "gateway.lab.internal",
            "onvif-edge.lab.internal", "mikrotik.lab.internal"
        };
        string[] pairs =
        {
            "admin:admin", "admin:password", "root:root", "root:admin",
            "user:user", "guest:guest", "ubnt:ubnt", "support:support"
        };
        foreach (var host in hosts)
        foreach (var pair in pairs)
        foreach (var method in new[] { "GET", "POST", "PUT" })
            yield return new object[] { host, pair, method };
    }

    [Theory]
    [MemberData(nameof(ValidDefaultBasicScenarios))]
    public async Task R118_Recognizes_Real_Parsed_Default_Basic_Without_Promoting_An_Alert(
        string host, string pair, string method)
    {
        // Exercise capture-time derivation and redaction instead of setting
        // the internal trust bit in a JSON fixture.
        var encoded = Convert.ToBase64String(Encoding.ASCII.GetBytes(pair));
        var raw = $"{method} /onvif/device_service HTTP/1.1\r\nHost: {host}\r\nAuthorization: Basic {encoded}\r\n\r\n";
        Assert.True(HttpLight.TryParseHttp(Encoding.ASCII.GetBytes(raw), out var parsed));
        Assert.True(parsed.ObservedDefaultBasicCredential);
        Assert.DoesNotContain(encoded, parsed.JoinedHeaderLines, StringComparison.Ordinal);
        Assert.Contains("Authorization: [REDACTED]", parsed.JoinedHeaderLines);

        var record = DeviceRecord(host);
        record.HttpMethod = parsed.Method;
        record.HttpHost = parsed.Host;
        record.HttpUri = parsed.Path;
        record.HttpRequestHeaders = parsed.JoinedHeaderLines;
        record.HttpBasicDefaultCredentialObserved = parsed.ObservedDefaultBasicCredential;

        var rule = new R118_DefaultCredentialIoTAttemptRule();
        var result = await rule.EvaluateAsync(Context(record));
        Assert.True(result.Matched, $"Expected R118 recognition for {host} and {method}.");
        var evt = Assert.Single(result.Events);
        Assert.Equal(0.76, evt.ConfidenceScore, 6);
        var policy = RulePrecisionRuntimeEvaluator.Evaluate(
            rule.Descriptor, evt, record, RuleMode.Alert, "Research");
        Assert.False(policy.AllowsAlert);
        Assert.False(policy.ConfidenceSatisfied);
        Assert.DoesNotContain(encoded, System.Text.Json.JsonSerializer.Serialize(evt),
            StringComparison.Ordinal);
    }

    public static IEnumerable<object[]> FalseIoTAuthenticationScenarios()
    {
        const string host = "camera-lab.internal";
        const string defaultBasic = "Basic YWRtaW46YWRtaW4=";
        yield return new object[] { "no-auth", host, "Host: camera-lab.internal", "" };
        yield return new object[] { "bearer", host, "Host: camera-lab.internal\r\nAuthorization: Bearer YWRtaW46YWRtaW4=", "" };
        yield return new object[] { "digest", host, "Host: camera-lab.internal\r\nAuthorization: Digest username=admin", "" };
        yield return new object[] { "nondefault", host, "Host: camera-lab.internal\r\nAuthorization: Basic YWRtaW46c3Ryb25nLXBhc3M=", "" };
        yield return new object[] { "invalid-base64", host, "Host: camera-lab.internal\r\nAuthorization: Basic !!!", "" };
        yield return new object[] { "duplicate-auth", host, "Host: camera-lab.internal\r\nAuthorization: " + defaultBasic + "\r\nAuthorization: " + defaultBasic, "" };
        yield return new object[] { "duplicate-host", host, "Host: camera-lab.internal\r\nHost: camera-lab.internal\r\nAuthorization: " + defaultBasic, "" };
        yield return new object[] { "host-conflict", host, "Host: unrelated.example\r\nAuthorization: " + defaultBasic, "" };
        yield return new object[] { "host-comma", host, "Host: camera-lab.internal, unrelated.example\r\nAuthorization: " + defaultBasic, "" };
        yield return new object[] { "host-userinfo", "admin@camera-lab.internal", "Host: admin@camera-lab.internal\r\nAuthorization: " + defaultBasic, "" };
        yield return new object[] { "marketing-name", "camerastore.example", "Host: camerastore.example\r\nAuthorization: " + defaultBasic, "" };
        yield return new object[] { "description-only", host, "Host: camera-lab.internal", "help page says admin:admin; not a login" };
        yield return new object[] { "x-authorization", host, "Host: camera-lab.internal\r\nX-Authorization: " + defaultBasic, "" };
        yield return new object[] { "proxy-auth", host, "Host: camera-lab.internal\r\nProxy-Authorization: " + defaultBasic, "" };
        yield return new object[] { "redacted-without-proof", host, "Host: camera-lab.internal\r\nAuthorization: [REDACTED]", "" };
        yield return new object[] { "host-header-port-disagrees", host, "Host: camera-lab.internal:8080\r\nAuthorization: " + defaultBasic, "" };
    }

    [Theory]
    [MemberData(nameof(FalseIoTAuthenticationScenarios))]
    public async Task R118_Rejects_Untrusted_And_Ambiguous_Device_Authentication(
        string scenario, string host, string headers, string info)
    {
        var record = DeviceRecord(host);
        record.HttpRequestHeaders = headers;
        record.Info = info;
        var rule = new R118_DefaultCredentialIoTAttemptRule();
        var result = await rule.EvaluateAsync(Context(record));
        Assert.False(result.Matched, $"False R118 raw match in {scenario}.");
    }

    public static IEnumerable<object[]> CloudCredentialCandidates()
    {
        var cases = new[]
        {
            new[] { "ec2-ipv4", "169.254.169.254", "169.254.169.254", "/latest/meta-data/iam/security-credentials/test-role" },
            new[] { "azure-ipv4", "169.254.169.254", "169.254.169.254", "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=x" },
            new[] { "gcp-ipv4", "169.254.169.254", "metadata.google.internal", "/computeMetadata/v1/instance/service-accounts/default/token" },
            new[] { "ecs-ipv4", "169.254.170.2", "169.254.170.2", "/v2/credentials/container123" },
            new[] { "alibaba-ipv4", "100.100.100.200", "100.100.100.200", "/latest/meta-data/ram/security-credentials/test-role" },
            new[] { "ec2-ipv6", "fd00:ec2::254", "[fd00:ec2::254]", "/latest/meta-data/iam/security-credentials/test-role" },
            new[] { "gcp-ipv6", "fd20:ce::254", "[fd20:ce::254]", "/computeMetadata/v1/instance/service-accounts/default/token" }
        };
        foreach (var item in cases)
        foreach (var method in new[] { "GET", "HEAD" })
            yield return new object[] { item[0], item[1], item[2], item[3], method };
    }

    [Theory]
    [MemberData(nameof(CloudCredentialCandidates))]
    public async Task R163_Recognizes_Provider_Consistent_Metadata_Without_Inferring_Ssrf(
        string scenario, string ip, string host, string uri, string method)
    {
        var record = MetadataRecord(ip, host, uri);
        record.HttpMethod = method;
        var rule = new R163_SsrfMetadataServiceProbeRule();
        var result = await rule.EvaluateAsync(Context(record));
        Assert.True(result.Matched, $"Expected metadata-path recognition: {scenario}");
        var evt = Assert.Single(result.Events);
        Assert.Equal(0.62, evt.ConfidenceScore, 6);
        var policy = RulePrecisionRuntimeEvaluator.Evaluate(
            rule.Descriptor, evt, record, RuleMode.Alert, "Research");
        Assert.False(policy.AllowsAlert);
        Assert.False(policy.ConfidenceSatisfied);
    }

    public static IEnumerable<object[]> RejectedMetadataScenarios()
    {
        const string ip = "169.254.169.254";
        const string host = "169.254.169.254";
        const string credential = "/latest/meta-data/iam/security-credentials/example";
        yield return new object[] { "ordinary-instance-id", ip, host, "/latest/meta-data/instance-id", "GET", "webapp.exe", "Host: " + host };
        yield return new object[] { "wrong-socket", "192.0.2.88", host, credential, "GET", "webapp.exe", "Host: " + host };
        yield return new object[] { "wrong-host", ip, "portal.example", credential, "GET", "webapp.exe", "Host: portal.example" };
        yield return new object[] { "host-conflict", ip, host, credential, "GET", "webapp.exe", "Host: portal.example" };
        yield return new object[] { "duplicate-host", ip, host, credential, "GET", "webapp.exe", "Host: " + host + "\r\nHost: " + host };
        yield return new object[] { "host-comma", ip, host, credential, "GET", "webapp.exe", "Host: " + host + ", portal.example" };
        yield return new object[] { "userinfo-authority", ip, "admin@169.254.169.254", credential, "GET", "webapp.exe", "Host: admin@169.254.169.254" };
        yield return new object[] { "ec2-ecs-confusion", "169.254.170.2", "169.254.170.2", credential, "GET", "webapp.exe", "Host: 169.254.170.2" };
        yield return new object[] { "gcp-aws-v6-confusion", "fd00:ec2::254", "[fd00:ec2::254]", "/computeMetadata/v1/instance/service-accounts/default/token", "GET", "webapp.exe", "Host: [fd00:ec2::254]" };
        yield return new object[] { "post", ip, host, credential, "POST", "webapp.exe", "Host: " + host };
        yield return new object[] { "put", ip, host, credential, "PUT", "webapp.exe", "Host: " + host };
        yield return new object[] { "relative-traversal", ip, host, "/latest/meta-data/../meta-data/iam/security-credentials/x", "GET", "webapp.exe", "Host: " + host };
        yield return new object[] { "dot-segment", ip, host, "/latest/./meta-data/iam/security-credentials/x", "GET", "webapp.exe", "Host: " + host };
        yield return new object[] { "encoded-slash", ip, host, "/latest/meta-data/iam%2fsecurity-credentials/x", "GET", "webapp.exe", "Host: " + host };
        yield return new object[] { "encoded-dot", ip, host, "/latest/%2emeta-data/iam/security-credentials/x", "GET", "webapp.exe", "Host: " + host };
        yield return new object[] { "url-query-only", ip, host, "/search?next=/latest/meta-data/iam/security-credentials/x", "GET", "webapp.exe", "Host: " + host };
        yield return new object[] { "cross-provider-absolute", ip, host, "http://169.254.170.2/v2/credentials/test", "GET", "webapp.exe", "Host: " + host };
        yield return new object[] { "trusted-cloud-init", ip, host, credential, "GET", "/usr/bin/cloud-init", "Host: " + host };
        yield return new object[] { "trusted-gcp-agent", ip, host, credential, "GET", "/opt/google/google-guest-agent", "Host: " + host };
        yield return new object[] { "metadata-negotiation", ip, host, "/latest/api/token", "PUT", "webapp.exe", "Host: " + host };
        yield return new object[] { "unresolvable-host-only", "metadata.google.internal", "metadata.google.internal", "/computeMetadata/v1/instance/service-accounts/default/token", "GET", "webapp.exe", "Host: metadata.google.internal" };
    }

    [Theory]
    [MemberData(nameof(RejectedMetadataScenarios))]
    public async Task R163_Rejects_Metadata_Lookalikes_Without_Valid_Attribution(
        string scenario, string ip, string host, string uri, string method,
        string process, string headers)
    {
        var record = MetadataRecord(ip, host, uri);
        record.HttpMethod = method;
        record.ProcessName = process;
        record.HttpRequestHeaders = headers;
        var result = await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(Context(record));
        Assert.False(result.Matched, $"Uncorroborated metadata match: {scenario}");
    }

    [Theory]
    [InlineData("/home/analyst/bin/cloud-init")]
    [InlineData("/home/analyst/.local/bin/google-guest-agent")]
    [InlineData("C:\\Users\\analyst\\Downloads\\cloud-init.exe")]
    [InlineData("/tmp/cloud-init")]
    [InlineData("/mnt/shared/google-guest-agent")]
    public async Task R163_Does_Not_Trust_User_Writable_Cloud_Agent_Names(string process)
    {
        var record = MetadataRecord(
            "169.254.169.254", "169.254.169.254",
            "/latest/meta-data/iam/security-credentials/example");
        record.ProcessName = process;
        var result = await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(Context(record));
        Assert.True(result.Matched, "Untrusted executable basename must not suppress a metadata probe.");
        var evt = Assert.Single(result.Events);
        var policy = RulePrecisionRuntimeEvaluator.Evaluate(
            new R163_SsrfMetadataServiceProbeRule().Descriptor, evt, record,
            RuleMode.Alert, "Research");
        Assert.False(policy.AllowsAlert);
    }

    private static TrafficRecord DeviceRecord(string host)
        => new()
        {
            Source = "198.51.100.42",
            Destination = "192.0.2.50",
            DestinationPort = 80,
            Protocol = "TCP",
            ApplicationProtocol = "HTTP",
            HttpMethod = "POST",
            HttpHost = host,
            HttpUri = "/onvif/device_service",
            ProcessName = "synthetic-administration-client.exe"
        };

    private static TrafficRecord MetadataRecord(string ip, string host, string uri)
        => new()
        {
            Source = "10.42.0.19",
            Destination = ip,
            DestinationPort = 80,
            Protocol = "TCP",
            ApplicationProtocol = "HTTP",
            HttpMethod = "GET",
            HttpHost = host,
            HttpUri = uri,
            HttpRequestHeaders = "Host: " + host,
            ProcessName = "unapproved-webapp.exe"
        };
}
