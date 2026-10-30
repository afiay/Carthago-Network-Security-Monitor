// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. Parser fixtures do not substitute for independent PCAPs.
using System;
using System.Text;
using System.Text.Json;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public sealed class DevOpsHttpParserProvenanceTests
{
    private static HttpLight.HttpInfo Parse(string request)
    {
        Assert.True(HttpLight.TryParseHttp(Encoding.ASCII.GetBytes(request), out var info));
        return info;
    }

    [Theory]
    [InlineData("pat")]
    [InlineData("token")]
    [InlineData("access_token")]
    [InlineData("personal_access_token")]
    public void Azure_Token_Shaped_Query_Is_Classified_And_Redacted_Before_Record(string parameter)
    {
        var secret = new string('A', 52);
        var parsed = Parse($"GET /org/_apis?{parameter}={secret} HTTP/1.1\r\nHost: dev.azure.com\r\n\r\n");
        Assert.True(parsed.ObservedAzureDevOpsPatUrlPattern);
        Assert.Contains("[REDACTED]", parsed.Path);
        Assert.DoesNotContain(secret, parsed.Path);
    }

    [Theory]
    [InlineData("pat", 51)]
    [InlineData("password", 52)]
    [InlineData("pat", 0)]
    public void Short_Or_Unrecognized_Query_Does_Not_Assert_Azure_Pat(string parameter, int length)
    {
        var parsed = Parse($"GET /org/_apis?{parameter}={new string('A', length)} HTTP/1.1\r\nHost: dev.azure.com\r\n\r\n");
        Assert.False(parsed.ObservedAzureDevOpsPatUrlPattern);
    }

    [Fact] public void Incomplete_Header_Section_Cannot_Assert_Azure_Pat()
    {
        var secret = new string('A', 52);
        var parsed = Parse($"GET /org/_apis?pat={secret} HTTP/1.1\r\nHost: dev.azure.com\r\n");
        Assert.False(parsed.ObservedAzureDevOpsPatUrlPattern);
        Assert.DoesNotContain(secret, parsed.Path);
    }

    [Fact] public void Exact_Circle_Token_Is_Classified_And_Header_Value_Redacted()
    {
        var secret = new string('a', 40);
        var parsed = Parse($"GET /api/v2/project HTTP/1.1\r\nHost: circleci.com\r\nCircle-Token: {secret}\r\n\r\n");
        Assert.True(parsed.ObservedCircleCiTokenPattern);
        Assert.Contains("Circle-Token: [REDACTED]", parsed.JoinedHeaderLines);
        Assert.DoesNotContain(secret, parsed.JoinedHeaderLines);
    }

    [Theory]
    [InlineData(39)]
    [InlineData(41)]
    public void Invalid_Circle_Token_Length_Is_Not_Observed(int length)
    {
        var parsed = Parse($"GET /api/v2/project HTTP/1.1\r\nHost: circleci.com\r\nCircle-Token: {new string('a', length)}\r\n\r\n");
        Assert.False(parsed.ObservedCircleCiTokenPattern);
    }

    [Fact] public void Duplicate_Circle_Token_Headers_Are_Ambiguous()
    {
        var secret = new string('a', 40);
        var parsed = Parse($"GET /api/v2/project HTTP/1.1\r\nHost: circleci.com\r\nCircle-Token: {secret}\r\nCircle-Token: {secret}\r\n\r\n");
        Assert.False(parsed.ObservedCircleCiTokenPattern);
        Assert.DoesNotContain(secret, parsed.JoinedHeaderLines);
    }

    [Fact] public void Incomplete_Circle_Token_Header_Block_Is_Not_Observed()
    {
        var parsed = Parse($"GET /api/v2/project HTTP/1.1\r\nHost: circleci.com\r\nCircle-Token: {new string('a', 40)}\r\n");
        Assert.False(parsed.ObservedCircleCiTokenPattern);
    }

    [Fact] public void Generic_Authorization_Header_Is_Not_Circle_Token_Proof()
    {
        var parsed = Parse($"GET /api/v2/project HTTP/1.1\r\nHost: circleci.com\r\nAuthorization: Bearer {new string('a', 40)}\r\n\r\n");
        Assert.False(parsed.ObservedCircleCiTokenPattern);
    }

    [Fact] public void Imported_Json_Cannot_Set_Parser_Only_Token_Flags()
    {
        var imported = JsonSerializer.Deserialize<TrafficRecord>(
            "{\"HttpAzureDevOpsPatUrlObserved\":true,\"HttpCircleCiTokenPatternObserved\":true}");
        Assert.NotNull(imported);
        Assert.False(imported!.HttpAzureDevOpsPatUrlObserved);
        Assert.False(imported.HttpCircleCiTokenPatternObserved);
    }
}
