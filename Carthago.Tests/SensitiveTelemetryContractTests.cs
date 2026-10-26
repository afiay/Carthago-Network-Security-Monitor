using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Carthago.Services;
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
    public async Task R118_Telnet_Password_Policy_Example_Is_Not_A_Login_Attempt()
    {
        var record = new TrafficRecord
        {
            Source = "10.1.1.25", Destination = "10.1.1.50", DestinationPort = 23,
            Protocol = "TCP", Info = "telnet password policy: login must never use admin:admin"
        };

        Assert.False((await new R118_DefaultCredentialIoTAttemptRule().EvaluateAsync(Context(record))).Matched);
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
    public async Task R118_Uses_Wire_Derived_Evidence_After_Authorization_Is_Redacted()
    {
        var request = "GET /admin HTTP/1.1\r\n"
                    + "Host: camera-lab.internal\r\n"
                    + "Authorization: Basic YWRtaW46YWRtaW4=\r\n\r\n";
        Assert.True(HttpLight.TryParseHttp(Encoding.ASCII.GetBytes(request), out var parsed));

        var record = new TrafficRecord
        {
            Source = "192.0.2.21",
            Destination = "192.0.2.50",
            DestinationPort = 8080,
            Protocol = "HTTP",
            HttpMethod = parsed.Method,
            HttpHost = parsed.Host,
            HttpUri = parsed.Path,
            HttpRequestHeaders = parsed.JoinedHeaderLines,
            HttpBasicDefaultCredentialObserved = parsed.ObservedDefaultBasicCredential
        };

        Assert.DoesNotContain("YWRtaW46YWRtaW4=", record.HttpRequestHeaders);
        Assert.True(RulePrecisionCatalog.Validate("R118", record).CanEvaluate);
        var rule = new R118_DefaultCredentialIoTAttemptRule();
        var result = await rule.EvaluateAsync(Context(record));
        Assert.True(result.Matched);
        Assert.Equal(RuleMode.Shadow,
            RulePrecisionRuntimeEvaluator.Evaluate(
                rule.Descriptor, Assert.Single(result.Events), record, RuleMode.Alert, "Research").EffectiveMode);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task R118_Does_Not_Persist_Credential_Bearing_Info_In_Either_Evidence_Format(bool telnet)
    {
        var record = telnet
            ? new TrafficRecord
            {
                Source = "192.0.2.30", Destination = "192.0.2.50",
                DestinationPort = 23, Protocol = "TCP",
                Info = "telnet login admin:admin factory default; private diagnostic note"
            }
            : new TrafficRecord
            {
                Source = "192.0.2.30", Destination = "192.0.2.50",
                DestinationPort = 8080, Protocol = "HTTP",
                HttpMethod = "GET", HttpHost = "camera-lab.internal",
                HttpUri = "/admin",
                HttpRequestHeaders = "Authorization: Basic YWRtaW46YWRtaW4=",
                Info = "support ticket contains admin:admin and private diagnostic note"
            };

        var result = await new R118_DefaultCredentialIoTAttemptRule().EvaluateAsync(Context(record));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.NotNull(evt.StructuredEvidence);

        var evidence = string.Join(" ", new[] { evt.Evidence ?? string.Empty }
            .Concat(evt.StructuredEvidence!.Items.Select(item => item.Value)));
        Assert.DoesNotContain("admin:admin", evidence);
        Assert.DoesNotContain("private diagnostic note", evidence);
        Assert.DoesNotContain("YWRtaW46YWRtaW4=", evidence);
        Assert.DoesNotContain(evt.StructuredEvidence.Items, item => item.Key == "iot.info");
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

    [Theory]
    [InlineData("169.254.170.2")]
    [InlineData("100.100.100.200")]
    public async Task R163_Does_Not_Trust_CrossProvider_Metadata_Host(string destination)
    {
        // A Host header naming AWS EC2 IMDS must not authenticate an
        // unrelated ECS or Alibaba metadata destination.
        var record = MetadataRecord("/latest/meta-data/iam/security-credentials/app", "webapp.exe");
        record.Destination = destination;

        Assert.False((await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(Context(record))).Matched);
        Assert.False(RulePrecisionCatalog.Validate("R163", record).CanEvaluate);
    }

    [Fact]
    public async Task R163_Requires_Observed_Ip_Destination_Not_Only_Metadata_Dns_Name()
    {
        // A DNS label in the network destination is not evidence of the
        // actual remote socket address. Keep metadata.google.internal valid
        // as an HTTP Host alias only when capture supplies its real IP.
        var record = MetadataRecord("/computeMetadata/v1/instance/service-accounts/default/token", "webapp.exe");
        record.Destination = "metadata.google.internal";
        record.HttpHost = "metadata.google.internal";

        Assert.False((await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(Context(record))).Matched);
        Assert.False(RulePrecisionCatalog.Validate("R163", record).CanEvaluate);
    }

    [Fact]
    public async Task R163_Accepts_Google_Metadata_Dns_Name_At_Shared_LinkLocal_Address()
    {
        // GCP resolves metadata.google.internal to 169.254.169.254.
        // The hostname and destination differ but represent one endpoint.
        var record = MetadataRecord("/computeMetadata/v1/instance/service-accounts/default/token", "webapp.exe");
        record.HttpHost = "metadata.google.internal";

        Assert.True((await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(Context(record))).Matched);
    }

    [Fact]
    public async Task R163_Rejects_Google_Metadata_Host_With_Aws_Credential_Path()
    {
        // Do not let a cross-provider Host/path combination stand in
        // for a validated metadata-service request.
        var record = MetadataRecord("/latest/meta-data/iam/security-credentials/app", "webapp.exe");
        record.HttpHost = "metadata.google.internal";

        Assert.False((await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(Context(record))).Matched);
    }

    [Theory]
    [InlineData("attacker@169.254.169.254")]
    [InlineData("169.254.169.254/credential-path")]
    [InlineData("169.254.169.254:8080")]
    public async Task R163_Rejects_Malformed_Or_Ambiguous_Http_Host(string host)
    {
        // A Host field is an authority, not an arbitrary URI. Never allow
        // userinfo, path segments, or an unrelated port to authenticate IMDS.
        var record = MetadataRecord("/latest/meta-data/iam/security-credentials/app", "webapp.exe");
        record.HttpHost = host;

        Assert.False((await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(Context(record))).Matched);
        Assert.False(RulePrecisionCatalog.Validate("R163", record).CanEvaluate);
    }

    [Theory]
    [InlineData("http://169.254.170.2/latest/meta-data/iam/security-credentials/app")]
    [InlineData("http://attacker@169.254.169.254/latest/meta-data/iam/security-credentials/app")]
    public async Task R163_Rejects_Absolute_Request_Target_With_Mismatched_Or_Userinfo_Authority(string target)
    {
        var record = MetadataRecord(target, "webapp.exe");

        Assert.False((await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(Context(record))).Matched);
        Assert.False(RulePrecisionCatalog.Validate("R163", record).CanEvaluate);
    }

    [Fact]
    public async Task R163_Accepts_Absolute_Request_Target_At_Observed_Metadata_Endpoint()
    {
        var record = MetadataRecord(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/app",
            "webapp.exe");

        Assert.True((await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(Context(record))).Matched);
        Assert.True(RulePrecisionCatalog.Validate("R163", record).CanEvaluate);
    }

    [Theory]
    [InlineData("169.254.170.2", "/latest/meta-data/iam/security-credentials/example-role")]
    [InlineData("169.254.170.2", "/metadata/identity/oauth2/token")]
    [InlineData("100.100.100.200", "/v2/credentials/ecs-task-id")]
    [InlineData("100.100.100.200", "/computeMetadata/v1/instance/service-accounts/default/token")]
    [InlineData("169.254.169.254", "/v2/credentials/ecs-task-id")]
    [InlineData("169.254.169.254", "/latest/meta-data/ram/security-credentials/example-role")]
    public async Task R163_Rejects_CrossProvider_Credential_Paths(string destination, string path)
    {
        // The socket destination and Host agree, but the credential endpoint
        // belongs to another provider. This is not an observed credential read.
        var record = MetadataRecord(path, "webapp.exe");
        record.Destination = destination;
        record.HttpHost = destination;

        Assert.False((await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(Context(record))).Matched);
        Assert.False(RulePrecisionCatalog.Validate("R163", record).CanEvaluate);
    }

    [Theory]
    [InlineData("169.254.170.2", "/v2/credentials/ecs-task-id")]
    [InlineData("100.100.100.200", "/latest/meta-data/ram/security-credentials/example-role")]
    [InlineData("169.254.169.254", "/latest/meta-data/iam/security-credentials/example-role")]
    [InlineData("169.254.169.254", "/metadata/identity/oauth2/token?api-version=2018-02-01")]
    [InlineData("169.254.169.254", "/computeMetadata/v1/instance/service-accounts/default/token")]
    public async Task R163_Recognizes_Documented_Provider_Credential_Endpoints(string destination, string path)
    {
        // A raw metadata credential request may match, but must remain Shadow
        // without independently verified inbound-to-outbound causality.
        var record = MetadataRecord(path, "webapp.exe");
        record.Destination = destination;
        record.HttpHost = destination;
        var rule = new R163_SsrfMetadataServiceProbeRule();

        var result = await rule.EvaluateAsync(Context(record));

        Assert.True(result.Matched);
        Assert.True(RulePrecisionCatalog.Validate("R163", record).CanEvaluate);
        Assert.Equal(RuleMode.Shadow,
            RulePrecisionRuntimeEvaluator.Evaluate(
                rule.Descriptor, Assert.Single(result.Events), record, RuleMode.Alert, "Research").EffectiveMode);
        Assert.Equal(84, rule.PrecisionProfile.MinimumConfidence);
    }

    [Theory]
    [InlineData("fd00:ec2::254", "[fd00:ec2::254]", "/latest/meta-data/iam/security-credentials/example-role")]
    [InlineData("fd20:ce::254", "[fd20:ce::254]", "/computeMetadata/v1/instance/service-accounts/default/token")]
    [InlineData("fd20:ce::254", "metadata.google.internal", "/computeMetadata/v1/instance/service-accounts/default/token")]
    [InlineData("fd00:0ec2:0:0:0:0:0:0254", "[fd00:ec2::254]", "/latest/meta-data/iam/security-credentials/example-role")]
    public async Task R163_Recognizes_Documented_Ipv6_Metadata_Credential_Endpoints(
        string destination, string host, string path)
    {
        // AWS EC2 and GCP publish different IPv6 metadata endpoints. A
        // bracketed HTTP Host must correspond to the observed IPv6 destination.
        var record = MetadataRecord(path, "webapp.exe");
        record.Destination = destination;
        record.HttpHost = host;
        var rule = new R163_SsrfMetadataServiceProbeRule();

        var result = await rule.EvaluateAsync(Context(record));

        Assert.True(result.Matched);
        Assert.True(RulePrecisionCatalog.Validate("R163", record).CanEvaluate);
        Assert.Equal(RuleMode.Shadow,
            RulePrecisionRuntimeEvaluator.Evaluate(
                rule.Descriptor, Assert.Single(result.Events), record, RuleMode.Alert, "Research").EffectiveMode);
        Assert.Equal(84, rule.PrecisionProfile.MinimumConfidence);
    }

    [Theory]
    [InlineData("fd00:ec2::254", "[fd00:ec2::254]", "/computeMetadata/v1/instance/service-accounts/default/token")]
    [InlineData("fd20:ce::254", "[fd20:ce::254]", "/latest/meta-data/iam/security-credentials/example-role")]
    [InlineData("fd00:ec2::254", "[fd20:ce::254]", "/latest/meta-data/iam/security-credentials/example-role")]
    [InlineData("fd00:ec2::254", "metadata.google.internal", "/latest/meta-data/iam/security-credentials/example-role")]
    [InlineData("fd00:ec2::254", "fd00:ec2::254", "/latest/meta-data/iam/security-credentials/example-role")]
    [InlineData("fd00:ec2::254", "[fd00:ec2::254%25eth0]", "/latest/meta-data/iam/security-credentials/example-role")]
    [InlineData("fd00:ec2::254", "[fd00:ec2::254]:8080", "/latest/meta-data/iam/security-credentials/example-role")]
    public async Task R163_Rejects_Ipv6_Provider_Spoofing_And_Invalid_Host_Authorities(
        string destination, string host, string path)
    {
        var record = MetadataRecord(path, "webapp.exe");
        record.Destination = destination;
        record.HttpHost = host;

        Assert.False((await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(Context(record))).Matched);
        Assert.False(RulePrecisionCatalog.Validate("R163", record).CanEvaluate);
    }

    [Theory]
    [InlineData("fd00:ec2::254", "[fd00:ec2::254]",
        "http://[fd00:ec2::254]/latest/meta-data/iam/security-credentials/example-role", true)]
    [InlineData("fd00:ec2::254", "[fd00:ec2::254]",
        "http://[fd20:ce::254]/latest/meta-data/iam/security-credentials/example-role", false)]
    public async Task R163_Validates_Absolute_Form_Ipv6_Request_Targets(
        string destination, string host, string target, bool expectedMatch)
    {
        var record = MetadataRecord(target, "webapp.exe");
        record.Destination = destination;
        record.HttpHost = host;

        var result = await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(Context(record));

        Assert.Equal(expectedMatch, result.Matched);
        Assert.Equal(expectedMatch, RulePrecisionCatalog.Validate("R163", record).CanEvaluate);
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
