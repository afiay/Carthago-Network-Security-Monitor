// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// Negative-only qualification guard: no packet metadata can impersonate a
/// trusted identity-provider or authentication-server audit outcome.
/// These assertions are NOT detector-positive qualification.
/// </summary>
public sealed class R276R278FailClosedEvidenceTests
{
    [Theory]
    [InlineData("R276")]
    [InlineData("R277")]
    [InlineData("R278")]
    public async Task Spoofed_Audit_Labels_Cannot_Produce_Identity_Detection(string ruleId)
    {
        var record = NetworkBatch271275Context.Sample();
        record.Info = "signed idp audit consent grant approved offline_access mail.read; "
            + "legacy imap smtp AUTH success; 20 distinct users failed login password spray";
        record.HttpHost = "login.microsoftonline.com";
        record.HttpUri = "/adminconsent?scope=offline_access%20mail.read";
        record.ApplicationProtocol = "HTTPS";
        Assert.False(await Evaluate(ruleId, record));
    }

    [Theory]
    [InlineData("R276")]
    [InlineData("R277")]
    [InlineData("R278")]
    public async Task Missing_Identity_Source_Cannot_Produce_Identity_Detection(string ruleId)
    {
        var record = NetworkBatch271275Context.Sample();
        record.Source = null;
        record.Info = "failed login admin consent legacy protocol";
        Assert.False(await Evaluate(ruleId, record));
    }

    [Fact]
    public async Task Mail_Port_Without_Parsed_Auth_Command_Is_Not_Legacy_Login()
    {
        var record = NetworkBatch271275Context.Sample();
        record.DestinationPort = 993;
        record.ApplicationProtocol = "IMAPS";
        record.Info = "ordinary encrypted mail connection";
        Assert.False(await Evaluate("R277", record));
    }

    private static async Task<bool> Evaluate(string ruleId, TrafficRecord record)
    {
        var context = NetworkBatch271275Context.At(record);
        return ruleId switch
        {
            "R276" => (await new R276_OAuthConsentGrantAbuseIndicatorRule().EvaluateAsync(context)).Matched,
            "R277" => (await new R277_LegacyProtocolAuthenticationAttemptRule().EvaluateAsync(context)).Matched,
            "R278" => (await new R278_PasswordSprayLowAndSlowAcrossAccountsRule().EvaluateAsync(context)).Matched,
            _ => throw new ArgumentOutOfRangeException(nameof(ruleId))
        };
    }
}
