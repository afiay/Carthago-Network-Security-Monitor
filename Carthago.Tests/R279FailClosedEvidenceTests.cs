// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// Negative-only detector-entry-point qualification guard. HTTP login traffic and
/// user-agent labels cannot substitute for trusted account-linked failed auth outcomes.
/// These assertions do not constitute positive detector qualification.
/// </summary>
public sealed class R279FailClosedEvidenceTests
{
    [Theory]
    [InlineData("credential stuffing rotating user-agent 100 failed accounts")]
    [InlineData("login failure user-agent rotating password")]
    public async Task Spoofed_Auth_Labels_Cannot_Produce_Credential_Stuffing(string info)
    {
        var record = NetworkBatch271275Context.Sample();
        record.Info = info;
        record.HttpMethod = "POST";
        record.HttpHost = "login.example.test";
        record.HttpUri = "/login";
        record.ApplicationProtocol = "HTTPS";
        Assert.False((await new R279_CredentialStuffingRotatingUserAgentRule()
            .EvaluateAsync(NetworkBatch271275Context.At(record))).Matched);
    }

    [Fact]
    public async Task Missing_Source_Cannot_Be_Account_Linked_Failure()
    {
        var record = NetworkBatch271275Context.Sample();
        record.Source = null;
        record.HttpMethod = "POST";
        record.HttpUri = "/signin";
        record.Info = "user-agent rotation and failed logins";
        Assert.False((await new R279_CredentialStuffingRotatingUserAgentRule()
            .EvaluateAsync(NetworkBatch271275Context.At(record))).Matched);
    }

    [Fact]
    public async Task Benign_Http_Login_Request_Without_Auth_Outcome_Is_Not_Stuffing()
    {
        var record = NetworkBatch271275Context.Sample();
        record.HttpMethod = "GET";
        record.HttpHost = "login.example.test";
        record.HttpUri = "/login";
        record.ApplicationProtocol = "HTTPS";
        record.Info = "ordinary login page fetch";
        Assert.False((await new R279_CredentialStuffingRotatingUserAgentRule()
            .EvaluateAsync(NetworkBatch271275Context.At(record))).Matched);
    }
}
