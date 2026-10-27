// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;
public sealed class R136AdvancedAccuracyBatchTests
{
    private readonly R136_SessionCookieOverCleartextHttpRule _rule = new();
    [Fact] public async Task Attributed_Http_Session_Cookie_Matches()
    {
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch136140Context.At(NetworkBatch136140Context.Cookie()))).Events);
        Assert.Contains(evt.StructuredEvidence!.Items, x => x.Key == "session.cookieName" && x.Value == "jsessionid");
    }
    [Fact] public async Task Https_Cookie_Is_Protected()
    {
        var r = NetworkBatch136140Context.Cookie(); r.DestinationPort = 443;
        r.Protocol = "HTTPS"; r.ApplicationProtocol = "HTTPS"; r.ApplicationService = "HTTPS"; r.Sni = r.HttpHost;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r))).Matched);
    }
    [Fact] public async Task Missing_Tcp_And_Udp_Contradictions_Fail_Closed()
    {
        var a = NetworkBatch136140Context.Cookie(); a.IsTcp = false;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(a))).Matched);
        var b = NetworkBatch136140Context.Cookie(); b.IsUdp = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(b))).Matched);
    }
    [Fact] public async Task Analytics_Cookie_And_Info_Text_Are_Not_Sessions()
    {
        var a = NetworkBatch136140Context.Http(); a.HttpRequestHeaders += "\r\nCookie: analytics_id=abc123def456ghi789";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(a))).Matched);
        var b = NetworkBatch136140Context.Http(); b.Info = "Cookie: JSESSIONID=abc123def456ghi789";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(b))).Matched);
    }
    [Fact] public async Task Placeholder_Short_And_Low_Diversity_Values_Are_Negative()
    {
        foreach (var value in new[] { "short", "placeholder123456", "aaaaaaaaaaaa1234" })
        {
            var r = NetworkBatch136140Context.Http(); r.HttpRequestHeaders += "\r\nCookie: sessionid=" + value;
            Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r))).Matched);
        }
    }
    [Fact] public async Task Response_SetCookie_In_Request_Headers_Is_Not_Sent_Cookie()
    {
        var r = NetworkBatch136140Context.Http();
        r.HttpRequestHeaders += "\r\nSet-Cookie: JSESSIONID=abc123def456ghi789";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r))).Matched);
    }
    [Fact] public async Task Header_Name_Substring_Cannot_Spoof_Cookie()
    {
        var r = NetworkBatch136140Context.Http();
        r.HttpRequestHeaders += "\r\nX-Cookie: JSESSIONID=abc123def456ghi789";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r))).Matched);
    }
    [Fact] public async Task Cookie_And_Private_Route_Are_Redacted_Alert_Mode_Unchanged()
    {
        Assert.Equal(RuleRuntimeMode.Alert, _rule.PrecisionProfile.DefaultMode);
        Assert.Equal(82, _rule.PrecisionProfile.MinimumConfidence);
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch136140Context.At(NetworkBatch136140Context.Cookie("/private-secret-136")))).Events);
        Assert.DoesNotContain("abc123def456ghi789", evt.Evidence);
        Assert.DoesNotContain("private-secret-136", evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains("private-secret-136", StringComparison.Ordinal));
    }
}
