using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Engine.Rules.IotOt;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class SensitiveTelemetryContractTests
{
    [Fact]
    public async Task R118_Does_Not_Interpret_Administrator_Documentation_As_Credential_Attempt()
    {
        var record = new TrafficRecord
        {
            Source = "10.1.1.20", Destination = "10.1.1.50", DestinationPort = 8080,
            Protocol = "HTTP", HttpMethod = "GET", HttpHost = "camera.internal.local",
            HttpUri = "/admin/help/default-credentials",
            HttpRequestHeaders = "Host: camera.internal.local",
            Info = "camera login help: example admin:admin factory default",
            ProcessName = "browser.exe"
        };

        var result = await new R118_DefaultCredentialIoTAttemptRule().EvaluateAsync(Context(record));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R118_Recognizes_Observed_Basic_Authorization_Without_Plaintext_Info()
    {
        var record = new TrafficRecord
        {
            Source = "10.1.1.21", Destination = "10.1.1.50", DestinationPort = 8080,
            Protocol = "HTTP", HttpMethod = "GET", HttpHost = "camera.internal.local",
            HttpUri = "/admin", HttpRequestHeaders = "Authorization: Basic YWRtaW46YWRtaW4=",
            ProcessName = "curl.exe"
        };

        var rule = new R118_DefaultCredentialIoTAttemptRule();
        var result = await rule.EvaluateAsync(Context(record));

        Assert.True(result.Matched);
        Assert.Equal("R118", Assert.Single(result.Events).RuleId);
        Assert.True(RulePrecisionCatalog.Validate("R118", record).CanEvaluate);
    }

    [Fact]
    public async Task R118_Ordinary_Management_Login_Without_Default_Credentials_Is_Not_Detected()
    {
        var record = new TrafficRecord
        {
            Source = "10.1.1.22", Destination = "10.1.1.50", DestinationPort = 8080,
            Protocol = "HTTP", HttpMethod = "GET", HttpHost = "camera.internal.local",
            HttpUri = "/admin", HttpRequestHeaders = "Authorization: Basic YWRtaW46c3Ryb25nLXBhc3M=",
            Info = "camera login admin console", ProcessName = "browser.exe"
        };

        Assert.False((await new R118_DefaultCredentialIoTAttemptRule().EvaluateAsync(Context(record))).Matched);
    }

    [Fact]
    public async Task R118_Malformed_Basic_Authentication_Does_Not_Qualify()
    {
        var record = new TrafficRecord
        {
            Source = "10.1.1.24", Destination = "10.1.1.50", DestinationPort = 8080,
            Protocol = "HTTP", HttpMethod = "GET", HttpHost = "camera.internal.local",
            HttpUri = "/admin", HttpRequestHeaders = "Authorization: Basic not-base64!",
            Info = "camera administration console"
        };

        Assert.False((await new R118_DefaultCredentialIoTAttemptRule().EvaluateAsync(Context(record))).Matched);
        Assert.Contains("device_authentication_attempt", RulePrecisionCatalog.Validate("R118", record).MissingFields);
    }

    [Fact]
    public async Task R118_Telnet_Provisioning_Candidate_Stays_Shadow_Below_Existing_Precision_Floor()
    {
        var record = new TrafficRecord
        {
            Source = "10.1.1.23", Destination = "10.1.1.50", DestinationPort = 23,
            Protocol = "TCP", Info = "telnet login admin:admin factory default"
        };

        var rule = new R118_DefaultCredentialIoTAttemptRule();
        var result = await rule.EvaluateAsync(Context(record));
        Assert.True(result.Matched);
        var decision = RulePrecisionRuntimeEvaluator.Evaluate(rule.Descriptor, Assert.Single(result.Events), record, RuleMode.Alert, "Research");

        Assert.Equal(RuleMode.Shadow, decision.EffectiveMode);
        Assert.False(decision.ConfidenceSatisfied);
        Assert.Equal(86, rule.PrecisionProfile.MinimumConfidence);
    }

    [Fact]
    public async Task R163_Does_Not_Mistake_Normal_Azure_Metadata_Lookup_For_Credential_Theft()
    {
        var record = MetadataRecord("/metadata/instance?api-version=2021-02-01", "webapp.exe");
        record.HttpRequestHeaders = "Metadata: true";

        Assert.False((await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(Context(record))).Matched);
    }

    [Fact]
    public async Task R163_Does_Not_Trust_Forged_Metadata_Host_Header()
    {
        var record = MetadataRecord("/latest/meta-data/iam/security-credentials/app", "webapp.exe");
        record.Destination = "198.51.100.20";

        Assert.False((await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(Context(record))).Matched);
    }

    [Fact]
    public async Task R163_Credential_Request_Still_Matches_When_Host_Includes_Standard_Port()
    {
        var record = MetadataRecord("/latest/meta-data/iam/security-credentials/app", "webapp.exe");
        record.HttpHost = "169.254.169.254:80";

        Assert.True((await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(Context(record))).Matched);
    }

    [Fact]
    public async Task R163_Process_Name_With_Metadata_Word_Is_Not_A_Trusted_Cloud_Agent()
    {
        var record = MetadataRecord("/latest/meta-data/iam/security-credentials/app", "metadata-siphon.exe");

        Assert.True((await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(Context(record))).Matched);
    }

    [Theory]
    [InlineData("amazon-ssm-agent.exe")]
    [InlineData("cloud-init")]
    [InlineData("google-guest-agent")]
    public async Task R163_Approved_Cloud_Metadata_Agents_Remain_Unmatched(string process)
    {
        var record = MetadataRecord("/latest/meta-data/iam/security-credentials/app", process);
        record.HttpRequestHeaders = "X-aws-ec2-metadata-token: routine-imdsv2-token";

        Assert.False((await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(Context(record))).Matched);
    }

    [Fact]
    public async Task R163_Unattributed_Metadata_Credential_Request_Is_Never_Alert_Eligible()
    {
        var record = MetadataRecord("/latest/meta-data/iam/security-credentials/app", null);
        record.HttpRequestHeaders = "X-aws-ec2-metadata-token: routine-imdsv2-token";
        var rule = new R163_SsrfMetadataServiceProbeRule();
        var result = await rule.EvaluateAsync(Context(record));

        Assert.True(result.Matched);
        var decision = RulePrecisionRuntimeEvaluator.Evaluate(rule.Descriptor, Assert.Single(result.Events), record, RuleMode.Alert, "Research");
        Assert.Equal(RuleMode.Shadow, decision.EffectiveMode);
        Assert.Contains("process.name", decision.MissingFields);
        Assert.Equal(84, rule.PrecisionProfile.MinimumConfidence);
    }

    [Fact]
    public async Task R163_Direct_Metadata_Credential_Lookup_From_Ordinary_Process_Remains_Shadow()
    {
        var record = MetadataRecord("/latest/meta-data/iam/security-credentials/app", "powershell.exe");
        record.HttpRequestHeaders = "X-aws-ec2-metadata-token: routine-imdsv2-token";
        var rule = new R163_SsrfMetadataServiceProbeRule();
        var result = await rule.EvaluateAsync(Context(record));

        Assert.True(result.Matched);
        var decision = RulePrecisionRuntimeEvaluator.Evaluate(rule.Descriptor, Assert.Single(result.Events), record, RuleMode.Alert, "Research");
        Assert.Equal(RuleMode.Shadow, decision.EffectiveMode);
        Assert.False(decision.ConfidenceSatisfied);
    }

    private static TrafficRecord MetadataRecord(string path, string? process) => new()
    {
        Source = "10.1.1.30", Destination = "169.254.169.254", DestinationPort = 80,
        Protocol = "HTTP", HttpMethod = "GET", HttpHost = "169.254.169.254",
        HttpUri = path, ProcessName = process
    };

    private static RuleEvaluationContext Context(TrafficRecord record)
        => new(record, Sensitivity.Balanced, DateTime.UtcNow);
}
