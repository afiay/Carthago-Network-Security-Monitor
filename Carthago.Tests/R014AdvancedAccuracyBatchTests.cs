// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>R014: credential-bearing cleartext commands, never envelope noise.</summary>
[Collection("Legacy rules R011-R015 isolated")]
public sealed class R014AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R014_CleartextCredentialsRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 6, 0, 0, DateTimeKind.Utc);
    public R014AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Flow(int port = 21, string? info = "PASS secret-canary",
        string protocol = "TCP", string destination = "10.14.0.2")
        => new() { Source = "10.14.0.1", Destination = destination, Protocol = protocol,
            DestinationPort = port, Info = info, Length = 200 };

    private async Task<RuleEvaluationResult> See(TrafficRecord r, int second = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(second)));

    [Fact]
    public async Task Ftp_Pass_Command_Produces_Critical_Exposure_Candidate_Without_Secret()
    {
        var evt = Assert.Single((await See(Flow())).Events);
        Assert.Equal("R014", evt.RuleId);
        Assert.Equal(SeverityLevel.Critical, evt.Severity);
        Assert.Contains("FTP", evt.Description);
        Assert.DoesNotContain("secret-canary", evt.Description);
    }

    [Fact]
    public async Task Ftp_Username_Alone_Is_Not_A_Password_Exposure()
    {
        Assert.False((await See(Flow(info: "USER admin"))).Matched);
    }

    [Fact]
    public async Task Observed_Http_Basic_Header_On_Cleartext_Http_Is_A_Candidate()
    {
        const string encoded = "YWRtaW46cGFzc3dvcmQ=";
        var record = Flow(port: 80, info: "GET / HTTP/1.1", protocol: "HTTP");
        record.HttpRequestHeaders = "Host: example.invalid\r\nAuthorization: Basic " + encoded + "\r\n";
        var evt = Assert.Single((await See(record)).Events);
        Assert.Contains("HTTP", evt.Description);
        Assert.DoesNotContain(encoded, evt.Description);
    }

    [Fact]
    public async Task Smtp_Auth_Plain_With_Encoded_Value_Is_A_Candidate()
    {
        const string encoded = "AHVzZXIAcGFzc3dvcmQ=";
        var evt = Assert.Single((await See(Flow(port: 25, info: "AUTH PLAIN " + encoded))).Events);
        Assert.Contains("SMTP", evt.Description);
        Assert.DoesNotContain(encoded, evt.Description);
    }

    [Fact]
    public async Task Smtp_Envelope_And_Auth_Negotiation_Are_Not_Credentials()
    {
        foreach (var info in new[] { "MAIL FROM:<sender@example.invalid>", "RCPT TO:<recipient@example.invalid>",
            "AUTH LOGIN", "220 smtp.example.invalid ESMTP", "EHLO workstation" })
            Assert.False((await See(Flow(port: 25, info: info))).Matched);
    }

    [Fact]
    public async Task Encrypted_Flows_Are_Not_Declared_Cleartext()
    {
        var ftpTls = Flow(); ftpTls.TlsVersion = "TLS 1.3";
        var https = Flow(port: 443, info: "PASS secret-canary"); https.Sni = "example.invalid";
        var smtps = Flow(port: 465, info: "AUTH PLAIN AHVzZXIAcGFzcw==");
        foreach (var record in new[] { ftpTls, https, smtps })
            Assert.False((await See(record)).Matched);
    }

    [Fact]
    public async Task Narrative_And_Proxy_Authorization_Text_Do_Not_Impersonate_Credential_Capture()
    {
        var narrative = Flow(info: "Documentation: PASS secret-canary");
        var proxy = Flow(port: 80, info: "GET / HTTP/1.1", protocol: "HTTP");
        proxy.HttpRequestHeaders = "Proxy-Authorization: Basic YWRtaW46cGFzcw==";
        Assert.False((await See(narrative)).Matched);
        Assert.False((await See(proxy)).Matched);
    }

    [Fact]
    public async Task Missing_Attribution_Nonpositive_Length_And_Udp_Are_Not_Credential_Evidence()
    {
        var noSource = Flow(); noSource.Source = null;
        var noDestination = Flow(); noDestination.Destination = "invalid";
        var zeroLength = Flow(); zeroLength.Length = 0;
        var udp = Flow(protocol: "UDP");
        foreach (var record in new[] { noSource, noDestination, zeroLength, udp })
            Assert.False((await See(record)).Matched);
    }

    [Fact]
    public async Task Cooldown_Suppresses_Repeat_But_Not_Independent_Destination()
    {
        Assert.True((await See(Flow())).Matched);
        var repeated = await See(Flow(), 1);
        Assert.True(repeated.Suppressed);
        Assert.Empty(repeated.Events);
        var other = await See(Flow(destination: "10.14.0.3"), 1);
        Assert.Equal("10.14.0.3", Assert.Single(other.Events).DestinationIp);
    }
}
