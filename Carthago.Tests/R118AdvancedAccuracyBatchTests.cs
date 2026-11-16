// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules.IotOt;
using Xunit;

namespace Carthago.Tests;

public sealed class R118AdvancedAccuracyBatchTests
{
    private readonly R118_DefaultCredentialIoTAttemptRule _rule = new();

    [Fact] public async Task Single_Parsed_Http_Basic_Default_Pair_Is_Candidate()
    {
        var result = await _rule.EvaluateAsync(NetworkBatch116120Context.Context(
            NetworkBatch116120Context.Basic(NetworkBatch116120Context.Source())));
        Assert.True(result.Matched);
        Assert.Equal(86, _rule.PrecisionProfile.MinimumConfidence);
        Assert.Contains(Assert.Single(result.Events).StructuredEvidence!.Items,
            item => item.Key == "matched_conditions");
    }

    [Theory]
    [InlineData("HTTP/1.1 401 Unauthorized")]
    [InlineData("HTTP/2 200")]
    [InlineData("http/3 403")]
    public async Task Response_Status_Line_Cannot_Qualify_As_Authentication_Request(string statusLine)
    {
        var record = NetworkBatch116120Context.Basic(NetworkBatch116120Context.Source());
        record.HttpMethod = statusLine;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record))).Matched);
    }

    [Fact] public async Task Post_Request_With_Default_Pair_Remains_Candidate()
    {
        var record = NetworkBatch116120Context.Basic(NetworkBatch116120Context.Source());
        record.HttpMethod = "POST";
        Assert.True((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record))).Matched);
    }

    [Fact] public async Task Duplicate_Authorization_Is_Ambiguous_Not_A_Login()
    {
        var record = NetworkBatch116120Context.Basic(NetworkBatch116120Context.Source());
        record.HttpRequestHeaders += "\r\nAuthorization: Basic YWRtaW46YWRtaW4=";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record))).Matched);
    }

    [Theory]
    [InlineData("X-Request-Id: trace\rAuthorization: Basic dXNlcjpwYXNz")]
    [InlineData("X-Request-Id: trace\rHost: unrelated.example")]
    [InlineData("X-Request-Id: trace\r")]
    public async Task Bare_Carriage_Return_Cannot_Hide_Authentication_Header(string header)
    {
        var record = NetworkBatch116120Context.Basic(NetworkBatch116120Context.Source());
        record.HttpRequestHeaders += "\r\n" + header;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record))).Matched);
    }

    [Theory]
    [InlineData("\r\n")]
    [InlineData("\n")]
    public async Task Valid_Header_Delimiters_Preserve_Default_Credential_Attempt(string delimiter)
    {
        var record = NetworkBatch116120Context.Basic(NetworkBatch116120Context.Source());
        record.HttpRequestHeaders += delimiter + "X-Request-Id: trace";
        Assert.True((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record))).Matched);
    }

    [Theory]
    [InlineData("X-Request-Id: trace\0Authorization: Basic dXNlcjpwYXNz")]
    [InlineData("X-Request-Id: trace\u0001Authorization: Basic dXNlcjpwYXNz")]
    [InlineData("X-Request-Id: trace\u007fAuthorization: Basic dXNlcjpwYXNz")]
    public async Task Control_Bytes_Cannot_Qualify_Authentication_Headers(string header)
    {
        var record = NetworkBatch116120Context.Basic(NetworkBatch116120Context.Source());
        record.HttpRequestHeaders += "\r\n" + header;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record))).Matched);
    }

    [Theory]
    [InlineData("Authorization : Basic YWRtaW46YWRtaW4=")]
    [InlineData("Authorization\t: Basic YWRtaW46YWRtaW4=")]
    public async Task Malformed_Authorization_Field_Name_Cannot_Qualify(string malformedHeader)
    {
        var record = NetworkBatch116120Context.Basic(NetworkBatch116120Context.Source());
        record.HttpRequestHeaders = "Host: " + record.HttpHost + "\r\n" + malformedHeader;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record))).Matched);
    }

    [Fact]
    public async Task Trusted_Default_Pair_Flag_Cannot_Override_Contradictory_Wire_Authorization()
    {
        var record = NetworkBatch116120Context.Basic(NetworkBatch116120Context.Source());
        record.HttpRequestHeaders = "Host: " + record.HttpHost
            + "\r\nAuthorization: Basic dXNlcjpwYXNz";
        Assert.True(record.HttpBasicDefaultCredentialObserved);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record))).Matched);
    }


    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Redacted_Authorization_Requires_Capture_Observation(bool observed)
    {
        var record = NetworkBatch116120Context.Basic(NetworkBatch116120Context.Source());
        record.HttpRequestHeaders = "Host: " + record.HttpHost
            + "\r\nAuthorization: [REDACTED]";
        record.HttpBasicDefaultCredentialObserved = observed;
        var result = await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record));
        Assert.Equal(observed, result.Matched);
    }

    [Fact] public async Task Unattributed_Device_Host_Cannot_Qualify()
    {
        var record = NetworkBatch116120Context.Basic(NetworkBatch116120Context.Source());
        record.HttpHost = null;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record))).Matched);
    }

    [Fact] public async Task Contradictory_Udp_And_Host_Sni_Are_Rejected()
    {
        var udp = NetworkBatch116120Context.Basic(NetworkBatch116120Context.Source());
        udp.IsUdp = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(udp))).Matched);
        var conflict = NetworkBatch116120Context.Basic(NetworkBatch116120Context.Source());
        conflict.Sni = "unrelated.example";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(conflict))).Matched);
    }

    [Fact] public async Task Genuine_Telnet_Default_Pair_Remains_Recognized()
    {
        var record = NetworkBatch116120Context.Telnet(NetworkBatch116120Context.Source());
        record.Info = "camera login: admin:admin";
        var result = await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record));
        Assert.True(result.Matched);
    }

    [Fact] public async Task Telnet_Over_Udp_Cannot_Assert_Default_Pair()
    {
        var record = NetworkBatch116120Context.Telnet(NetworkBatch116120Context.Source());
        record.Info = "camera login: admin:admin";
        record.IsTcp = false; record.IsUdp = true; record.Protocol = "UDP";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record))).Matched);
    }

    [Fact] public async Task Default_Credential_Wire_Value_Does_Not_Leak()
    {
        const string token = "YWRtaW46YWRtaW4=";
        var result = await _rule.EvaluateAsync(NetworkBatch116120Context.Context(
            NetworkBatch116120Context.Basic(NetworkBatch116120Context.Source())));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain(token, evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains(token, StringComparison.Ordinal));
    }
}
