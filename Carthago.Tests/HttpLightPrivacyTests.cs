// SPDX-License-Identifier: MIT
using System;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Engine.Rules.IotOt;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public sealed class HttpLightPrivacyTests
{
    [Theory]
    [InlineData("Authorization")]
    [InlineData("Proxy-Authorization")]
    [InlineData("Cookie")]
    [InlineData("Set-Cookie")]
    [InlineData("X-Api-Key")]
    [InlineData("X-aws-ec2-metadata-token")]
    [InlineData("X-Identity-Header")]
    [InlineData("X-Auth-Token")]
    [InlineData("X-Amz-Security-Token")]
    public void Sensitive_Http_Header_Values_Are_Redacted_Before_Record_Construction(string header)
    {
        const string sentinel = "synthetic-test-only-value-123";
        var request = string.Join("\r\n", new[]
        {
            "GET /latest/meta-data/instance-id HTTP/1.1",
            "Host: 169.254.169.254",
            header + ": " + sentinel,
            "User-Agent: CarthagoTest/1.0",
            "", ""
        });

        Assert.True(HttpLight.TryParseHttp(Encoding.ASCII.GetBytes(request), out var parsed));
        Assert.NotNull(parsed.JoinedHeaderLines);
        Assert.Contains(header + ": [REDACTED]", parsed.JoinedHeaderLines, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(sentinel, parsed.JoinedHeaderLines, StringComparison.Ordinal);
        Assert.Equal("169.254.169.254", parsed.Host);
        Assert.Equal("CarthagoTest/1.0", parsed.UserAgent);
    }

    [Fact]
    public void Non_Secret_Cloud_Protocol_Headers_Remain_Available_For_Diagnostics()
    {
        var request = "GET /computeMetadata/v1/instance/id HTTP/1.1\r\n"
                    + "Host: metadata.google.internal\r\n"
                    + "Metadata-Flavor: Google\r\n"
                    + "\r\n";

        Assert.True(HttpLight.TryParseHttp(Encoding.ASCII.GetBytes(request), out var parsed));
        Assert.Contains("Metadata-Flavor: Google", parsed.JoinedHeaderLines);
        Assert.Equal("metadata.google.internal", parsed.Host);
    }

    [Theory]
    [InlineData("Basic YWRtaW46YWRtaW4=", true)]
    [InlineData("bAsIc YWRtaW46YWRtaW4=", true)]
    [InlineData("Basic YWRtaW46c3Ryb25nLXBhc3M=", false)]
    [InlineData("Basic invalid!!", false)]
    public void Basic_Authentication_Produces_Only_A_Derived_Default_Credential_Indicator(
        string authorization, bool expected)
    {
        var request = "GET /admin HTTP/1.1\r\n"
                    + "Host: camera-lab.internal\r\n"
                    + "Authorization: " + authorization + "\r\n"
                    + "\r\n";

        Assert.True(HttpLight.TryParseHttp(Encoding.ASCII.GetBytes(request), out var parsed));
        Assert.Equal(expected, parsed.ObservedDefaultBasicCredential);
        Assert.Contains("Authorization: [REDACTED]", parsed.JoinedHeaderLines);
        Assert.DoesNotContain(authorization, parsed.JoinedHeaderLines);
    }
    [Fact]
    public void Imported_Json_Cannot_Assert_Trusted_Default_Basic_Capture_Flag()
    {
        // The trusted bit is capture-path-only. A replay/imported JSON record
        // cannot bypass redacted-header verification by claiming it is true.
        var imported = JsonSerializer.Deserialize<TrafficRecord>(
            "{\"Source\":\"198.51.100.182\",\"HttpBasicDefaultCredentialObserved\":true}");
        Assert.NotNull(imported);
        Assert.False(imported!.HttpBasicDefaultCredentialObserved);
    }

    [Fact]
    public void Synthetic_Onvif_Wire_Request_Derives_Trust_Before_Header_Redaction()
    {
        var raw = "POST /onvif/device_service HTTP/1.1\\r\\n"
                + "Host: nvr-lab.internal\\r\\n"
                + "Authorization: Basic YWRtaW46YWRtaW4=\\r\\n\\r\\n";

        Assert.True(HttpLight.TryParseHttp(Encoding.ASCII.GetBytes(raw), out var parsed));
        Assert.True(parsed.ObservedDefaultBasicCredential);
        Assert.Equal("nvr-lab.internal", parsed.Host);
        Assert.Equal("/onvif/device_service", parsed.Path);
        Assert.Contains("Authorization: [REDACTED]", parsed.JoinedHeaderLines);
        Assert.DoesNotContain("YWRtaW46YWRtaW4=", parsed.JoinedHeaderLines);
    }

    [Fact]
    public async Task R118_And_R163_Events_Do_Not_Expose_Synthetic_Credential_Bytes()
    {
        const string defaultBasic = "YWRtaW46YWRtaW4="; // Synthetic admin:admin fixture only.
        const string metadataToken = "synthetic-secret-token-do-not-persist";

        var iot = new TrafficRecord
        {
            Source = "198.51.100.70",
            Destination = "192.0.2.50",
            DestinationPort = 80,
            Protocol = "HTTP",
            ApplicationProtocol = "HTTP",
            HttpMethod = "GET",
            HttpHost = "camera-lab.internal",
            HttpUri = "/admin",
            HttpRequestHeaders = "Host: camera-lab.internal\r\nAuthorization: Basic " + defaultBasic,
            ProcessName = "unattributed-client.exe"
        };
        var metadata = new TrafficRecord
        {
            Source = "10.0.0.20",
            Destination = "169.254.169.254",
            DestinationPort = 80,
            Protocol = "HTTP",
            ApplicationProtocol = "HTTP",
            HttpMethod = "GET",
            HttpHost = "169.254.169.254",
            HttpUri = "/latest/meta-data/iam/security-credentials/test-role",
            HttpRequestHeaders = "Host: 169.254.169.254\r\nX-aws-ec2-metadata-token: " + metadataToken,
            ProcessName = "unapproved-webapp.exe"
        };

        var iotResult = await new R118_DefaultCredentialIoTAttemptRule().EvaluateAsync(
            new RuleEvaluationContext(iot, Sensitivity.Balanced, DateTime.UtcNow));
        var metadataResult = await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(
            new RuleEvaluationContext(metadata, Sensitivity.Balanced, DateTime.UtcNow));
        Assert.True(iotResult.Matched);
        Assert.True(metadataResult.Matched);

        var iotEvent = JsonSerializer.Serialize(Assert.Single(iotResult.Events));
        var metadataEvent = JsonSerializer.Serialize(Assert.Single(metadataResult.Events));
        Assert.DoesNotContain(defaultBasic, iotEvent, StringComparison.Ordinal);
        Assert.DoesNotContain("admin:admin", iotEvent, StringComparison.Ordinal);
        Assert.DoesNotContain("Authorization:", iotEvent, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(metadataToken, metadataEvent, StringComparison.Ordinal);
        Assert.DoesNotContain("X-aws-ec2-metadata-token:", metadataEvent, StringComparison.OrdinalIgnoreCase);
    }

}
