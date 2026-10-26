// SPDX-License-Identifier: MIT
using System;
using System.Text;
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
}
