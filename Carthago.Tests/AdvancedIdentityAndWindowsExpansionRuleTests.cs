using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;

namespace Carthago.Tests;

public sealed class AdvancedIdentityAndWindowsExpansionRuleTests
{
    [Fact]
    public async Task R275_matches_suspicious_device_code_request()
    {
        var rule = new R275_OAuthDeviceCodePhishingIndicatorRule();
        var result = await rule.EvaluateAsync(CreateContext(new TrafficRecord
        {
            Source = "10.0.0.60",
            Destination = "198.51.100.60",
            DestinationPort = 443,
            Protocol = "HTTPS",
            ApplicationProtocol = "HTTPS",
            ApplicationService = "HTTPS",
            HttpMethod = "POST",
            HttpHost = "login.microsoftonline.com",
            HttpUri = "/oauth2/v2.0/devicecode?client_id=x&device_code=y&user_code=z",
            HttpRequestHeaders = "Host: login.microsoftonline.com",
            IsTcp = true
        }));

        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R275", evt.RuleId);
        Assert.True(evt.ConfidenceScore >= 0.75);
    }

    [Fact]
    public async Task R275_ignores_ordinary_device_code_initiation()
    {
        var rule = new R275_OAuthDeviceCodePhishingIndicatorRule();
        var result = await rule.EvaluateAsync(CreateContext(new TrafficRecord
        {
            Source = "10.0.0.61",
            Destination = "198.51.100.61",
            DestinationPort = 443,
            Protocol = "HTTPS",
            ApplicationProtocol = "HTTPS",
            ApplicationService = "HTTPS",
            HttpMethod = "POST",
            HttpHost = "login.microsoftonline.com",
            HttpUri = "/oauth2/v2.0/devicecode?client_id=x&scope=openid",
            HttpRequestHeaders = "Host: login.microsoftonline.com",
            IsTcp = true
        }));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R275_ignores_device_code_without_user_code_abuse()
    {
        var result = await new R275_OAuthDeviceCodePhishingIndicatorRule().EvaluateAsync(CreateContext(new TrafficRecord
        {
            Source = "10.0.0.62", Destination = "198.51.100.62", Protocol = "HTTPS",
            HttpMethod = "POST", HttpHost = "login.microsoftonline.com",
            HttpUri = "/oauth2/v2.0/devicecode?client_id=x&device_code=y"
        }));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R343_matches_powershell_remoting_encoded_command()
    {
        var rule = new R343_PowerShellRemotingEncodedCommandRule();
        var result = await rule.EvaluateAsync(CreateContext(new TrafficRecord
        {
            Source = "10.0.0.70",
            Destination = "10.0.0.20",
            DestinationPort = 5985,
            Protocol = "TCP",
            Info = "powershell -enc SQBFAFgA encodedcommand Invoke-Command",
            IsTcp = true
        }));

        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R343", evt.RuleId);
        Assert.True(evt.ConfidenceScore >= 0.80);
    }

    [Fact]
    public async Task R343_ignores_local_encoded_powershell_without_remoting()
    {
        var rule = new R343_PowerShellRemotingEncodedCommandRule();
        var result = await rule.EvaluateAsync(CreateContext(new TrafficRecord
        {
            Source = "10.0.0.70",
            Destination = "10.0.0.70",
            DestinationPort = 443,
            Protocol = "TCP",
            Info = "powershell -enc SQBFAFgA encodedcommand",
            IsTcp = true
        }));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R343_ignores_winrm_port_without_remoting_command()
    {
        var result = await new R343_PowerShellRemotingEncodedCommandRule().EvaluateAsync(CreateContext(new TrafficRecord
        {
            Source = "10.0.0.72", Destination = "10.0.0.20", DestinationPort = 5985,
            Protocol = "TCP", Info = "powershell -enc SQBFAFgA encodedcommand", IsTcp = true
        }));

        Assert.False(result.Matched);
    }

    private static RuleEvaluationContext CreateContext(TrafficRecord record)
        => new(record, Sensitivity.Balanced, new DateTime(2026, 5, 3, 9, 0, 0, DateTimeKind.Utc));
}
