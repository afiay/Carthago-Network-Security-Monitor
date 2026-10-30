// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. All xUnit scenarios below are AUTHORED, UNEXECUTED.
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

internal static class NetworkBatch371380Context
{
    private static int _sequence;
    private static readonly DateTime Epoch = new(2026, 10, 30, 0, 0, 0, DateTimeKind.Utc);

    internal static TrafficRecord Request(string host, string path, string method = "GET")
    {
        var id = Interlocked.Increment(ref _sequence);
        return new TrafficRecord
        {
            Id = Guid.NewGuid(),
            Source = $"10.92.{id / 200}.{id % 200 + 1}",
            Destination = "8.8.8.8",
            IpVersion = 4, Protocol = "TCP", IsTcp = true, IsUdp = false,
            SourcePort = 50222, DestinationPort = 80,
            ApplicationProtocol = "HTTP", HttpMethod = method, HttpUri = path,
            HttpHost = host, Info = ""
        };
    }

    internal static TrafficRecord SameFlow(TrafficRecord original)
    {
        var copy = Request(original.HttpHost!, original.HttpUri!, original.HttpMethod!);
        copy.Source = original.Source;
        copy.Destination = original.Destination;
        return copy;
    }

    internal static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Epoch.AddSeconds(seconds));
}

public sealed class R371AdvancedAccuracyBatchTests
{
    private static Task<RuleEvaluationResult> Eval(TrafficRecord record)
        => new R371_MavenRepositoryCredentialUseRule().EvaluateAsync(NetworkBatch371380Context.At(record)).AsTask();

    // Six distinct regression invocations. No synthetic provider identity,
    // Info text, TLS metadata, or user-controlled query may imply an audit.
    [Theory]
    [InlineData("plausible")]
    [InlineData("descriptor-spoof")]
    [InlineData("tls-only")]
    [InlineData("wrong-host")]
    [InlineData("missing-source")]
    [InlineData("secret-query")]
    public async Task Missing_Trusted_Producer_Fails_Closed(string variation)
    {
        var record = NetworkBatch371380Context.Request("maven.pkg.github.com", "/owner/repo/package.jar", "GET");
        switch (variation)
        {
            case "descriptor-spoof":
                record.Info = "authenticated successful exfiltration confirmed by CloudTrail";
                break;
            case "tls-only":
                record.ApplicationProtocol = "TLS";
                break;
            case "wrong-host":
                record.HttpHost = "aws.example.attacker.invalid";
                break;
            case "missing-source":
                record.Source = null;
                break;
            case "secret-query":
                record.HttpUri = "/?token=synthetic-never-a-real-credential";
                break;
        }
        var result = await Eval(record);
        Assert.False(result.Matched);
        if (variation == "plausible")
            Assert.Contains(result.NoMatchReasons, x => x.Code == "MAVEN_CREDENTIAL_PROVENANCE_UNAVAILABLE");
    }

    [Fact]
    public void Original_Mode_Threshold_And_Confidence_Remain_Intact()
    {
        var profile = new R371_MavenRepositoryCredentialUseRule().PrecisionProfile;
        Assert.Equal(1, profile.Threshold);
        Assert.Equal(78, profile.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
    }
}

public sealed class R372AdvancedAccuracyBatchTests
{
    private static Task<RuleEvaluationResult> Eval(TrafficRecord record)
        => new R372_DependencyConfusionPackageNamePatternRule().EvaluateAsync(NetworkBatch371380Context.At(record)).AsTask();

    // Six distinct regression invocations. No synthetic provider identity,
    // Info text, TLS metadata, or user-controlled query may imply an audit.
    [Theory]
    [InlineData("plausible")]
    [InlineData("descriptor-spoof")]
    [InlineData("tls-only")]
    [InlineData("wrong-host")]
    [InlineData("missing-source")]
    [InlineData("secret-query")]
    public async Task Missing_Trusted_Producer_Fails_Closed(string variation)
    {
        var record = NetworkBatch371380Context.Request("registry.npmjs.org", "/internal-widget", "GET");
        switch (variation)
        {
            case "descriptor-spoof":
                record.Info = "authenticated successful exfiltration confirmed by CloudTrail";
                break;
            case "tls-only":
                record.ApplicationProtocol = "TLS";
                break;
            case "wrong-host":
                record.HttpHost = "aws.example.attacker.invalid";
                break;
            case "missing-source":
                record.Source = null;
                break;
            case "secret-query":
                record.HttpUri = "/?token=synthetic-never-a-real-credential";
                break;
        }
        var result = await Eval(record);
        Assert.False(result.Matched);
        if (variation == "plausible")
            Assert.Contains(result.NoMatchReasons, x => x.Code == "DEPENDENCY_PRIVATE_NAMESPACE_PROVENANCE_UNAVAILABLE");
    }

    [Fact]
    public void Original_Mode_Threshold_And_Confidence_Remain_Intact()
    {
        var profile = new R372_DependencyConfusionPackageNamePatternRule().PrecisionProfile;
        Assert.Equal(2, profile.Threshold);
        Assert.Equal(74, profile.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
    }
}

public sealed class R373AdvancedAccuracyBatchTests
{
    private static Task<RuleEvaluationResult> Eval(TrafficRecord record)
        => new R373_AWSSTSAssumeRoleBurstRule().EvaluateAsync(NetworkBatch371380Context.At(record)).AsTask();

    // Six distinct regression invocations. No synthetic provider identity,
    // Info text, TLS metadata, or user-controlled query may imply an audit.
    [Theory]
    [InlineData("plausible")]
    [InlineData("descriptor-spoof")]
    [InlineData("tls-only")]
    [InlineData("wrong-host")]
    [InlineData("missing-source")]
    [InlineData("secret-query")]
    public async Task Missing_Trusted_Producer_Fails_Closed(string variation)
    {
        var record = NetworkBatch371380Context.Request("sts.amazonaws.com", "/?Action=AssumeRole", "POST");
        switch (variation)
        {
            case "descriptor-spoof":
                record.Info = "authenticated successful exfiltration confirmed by CloudTrail";
                break;
            case "tls-only":
                record.ApplicationProtocol = "TLS";
                break;
            case "wrong-host":
                record.HttpHost = "aws.example.attacker.invalid";
                break;
            case "missing-source":
                record.Source = null;
                break;
            case "secret-query":
                record.HttpUri = "/?token=synthetic-never-a-real-credential";
                break;
        }
        var result = await Eval(record);
        Assert.False(result.Matched);
        if (variation == "plausible")
            Assert.Contains(result.NoMatchReasons, x => x.Code == "STS_ASSUMEROLE_ACTION_PROVENANCE_UNAVAILABLE");
    }

    [Fact]
    public void Original_Mode_Threshold_And_Confidence_Remain_Intact()
    {
        var profile = new R373_AWSSTSAssumeRoleBurstRule().PrecisionProfile;
        Assert.Equal(4, profile.Threshold);
        Assert.Equal(82, profile.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
    }
}

public sealed class R374AdvancedAccuracyBatchTests
{
    private static Task<RuleEvaluationResult> Eval(TrafficRecord record)
        => new R374_AWSIAMAccessKeyInURLRule().EvaluateAsync(NetworkBatch371380Context.At(record)).AsTask();

    // Six distinct regression invocations. No synthetic provider identity,
    // Info text, TLS metadata, or user-controlled query may imply an audit.
    [Theory]
    [InlineData("plausible")]
    [InlineData("descriptor-spoof")]
    [InlineData("tls-only")]
    [InlineData("wrong-host")]
    [InlineData("missing-source")]
    [InlineData("secret-query")]
    public async Task Missing_Trusted_Producer_Fails_Closed(string variation)
    {
        var record = NetworkBatch371380Context.Request("iam.amazonaws.com", "/?AWSAccessKeyId=AKIAEXAMPLEEXAMPLE00", "GET");
        switch (variation)
        {
            case "descriptor-spoof":
                record.Info = "authenticated successful exfiltration confirmed by CloudTrail";
                break;
            case "tls-only":
                record.ApplicationProtocol = "TLS";
                break;
            case "wrong-host":
                record.HttpHost = "aws.example.attacker.invalid";
                break;
            case "missing-source":
                record.Source = null;
                break;
            case "secret-query":
                record.HttpUri = "/?token=synthetic-never-a-real-credential";
                break;
        }
        var result = await Eval(record);
        Assert.False(result.Matched);
        if (variation == "plausible")
            Assert.Contains(result.NoMatchReasons, x => x.Code == "AWS_ACCESS_KEY_URL_PRIVACY_PROVENANCE_UNAVAILABLE");
    }

    [Fact]
    public void Original_Mode_Threshold_And_Confidence_Remain_Intact()
    {
        var profile = new R374_AWSIAMAccessKeyInURLRule().PrecisionProfile;
        Assert.Equal(1, profile.Threshold);
        Assert.Equal(82, profile.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
    }
}

public sealed class R376AdvancedAccuracyBatchTests
{
    private static Task<RuleEvaluationResult> Eval(TrafficRecord record)
        => new R376_AWSS3GetObjectBulkDownloadRule().EvaluateAsync(NetworkBatch371380Context.At(record)).AsTask();

    // Six distinct regression invocations. No synthetic provider identity,
    // Info text, TLS metadata, or user-controlled query may imply an audit.
    [Theory]
    [InlineData("plausible")]
    [InlineData("descriptor-spoof")]
    [InlineData("tls-only")]
    [InlineData("wrong-host")]
    [InlineData("missing-source")]
    [InlineData("secret-query")]
    public async Task Missing_Trusted_Producer_Fails_Closed(string variation)
    {
        var record = NetworkBatch371380Context.Request("s3.amazonaws.com", "/bucket/object", "GET");
        switch (variation)
        {
            case "descriptor-spoof":
                record.Info = "authenticated successful exfiltration confirmed by CloudTrail";
                break;
            case "tls-only":
                record.ApplicationProtocol = "TLS";
                break;
            case "wrong-host":
                record.HttpHost = "aws.example.attacker.invalid";
                break;
            case "missing-source":
                record.Source = null;
                break;
            case "secret-query":
                record.HttpUri = "/?token=synthetic-never-a-real-credential";
                break;
        }
        var result = await Eval(record);
        Assert.False(result.Matched);
        if (variation == "plausible")
            Assert.Contains(result.NoMatchReasons, x => x.Code == "S3_GETOBJECT_RESPONSE_BYTES_UNAVAILABLE");
    }

    [Fact]
    public void Original_Mode_Threshold_And_Confidence_Remain_Intact()
    {
        var profile = new R376_AWSS3GetObjectBulkDownloadRule().PrecisionProfile;
        Assert.Equal(4, profile.Threshold);
        Assert.Equal(82, profile.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
    }
}

public sealed class R377AdvancedAccuracyBatchTests
{
    private static Task<RuleEvaluationResult> Eval(TrafficRecord record)
        => new R377_AWSEC2UserDataMetadataProbeRule().EvaluateAsync(NetworkBatch371380Context.At(record)).AsTask();

    // Six distinct regression invocations. No synthetic provider identity,
    // Info text, TLS metadata, or user-controlled query may imply an audit.
    [Theory]
    [InlineData("plausible")]
    [InlineData("descriptor-spoof")]
    [InlineData("tls-only")]
    [InlineData("wrong-host")]
    [InlineData("missing-source")]
    [InlineData("secret-query")]
    public async Task Missing_Trusted_Producer_Fails_Closed(string variation)
    {
        var record = NetworkBatch371380Context.Request("169.254.169.254", "/latest/user-data", "GET");
        switch (variation)
        {
            case "descriptor-spoof":
                record.Info = "authenticated successful exfiltration confirmed by CloudTrail";
                break;
            case "tls-only":
                record.ApplicationProtocol = "TLS";
                break;
            case "wrong-host":
                record.HttpHost = "aws.example.attacker.invalid";
                break;
            case "missing-source":
                record.Source = null;
                break;
            case "secret-query":
                record.HttpUri = "/?token=synthetic-never-a-real-credential";
                break;
        }
        var result = await Eval(record);
        Assert.False(result.Matched);
        if (variation == "plausible")
            Assert.Contains(result.NoMatchReasons, x => x.Code == "EC2_METADATA_LINK_LOCAL_BOUNDARY_GA_OPEN");
    }

    [Fact]
    public void Original_Mode_Threshold_And_Confidence_Remain_Intact()
    {
        var profile = new R377_AWSEC2UserDataMetadataProbeRule().PrecisionProfile;
        Assert.Equal(1, profile.Threshold);
        Assert.Equal(82, profile.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
    }
}

public sealed class R379AdvancedAccuracyBatchTests
{
    private static Task<RuleEvaluationResult> Eval(TrafficRecord record)
        => new R379_AWSCloudTrailStopLoggingIndicatorRule().EvaluateAsync(NetworkBatch371380Context.At(record)).AsTask();

    // Six distinct regression invocations. No synthetic provider identity,
    // Info text, TLS metadata, or user-controlled query may imply an audit.
    [Theory]
    [InlineData("plausible")]
    [InlineData("descriptor-spoof")]
    [InlineData("tls-only")]
    [InlineData("wrong-host")]
    [InlineData("missing-source")]
    [InlineData("secret-query")]
    public async Task Missing_Trusted_Producer_Fails_Closed(string variation)
    {
        var record = NetworkBatch371380Context.Request("cloudtrail.us-east-1.amazonaws.com", "/", "POST");
        switch (variation)
        {
            case "descriptor-spoof":
                record.Info = "authenticated successful exfiltration confirmed by CloudTrail";
                break;
            case "tls-only":
                record.ApplicationProtocol = "TLS";
                break;
            case "wrong-host":
                record.HttpHost = "aws.example.attacker.invalid";
                break;
            case "missing-source":
                record.Source = null;
                break;
            case "secret-query":
                record.HttpUri = "/?token=synthetic-never-a-real-credential";
                break;
        }
        var result = await Eval(record);
        Assert.False(result.Matched);
        if (variation == "plausible")
            Assert.Contains(result.NoMatchReasons, x => x.Code == "CLOUDTRAIL_STOPLOGGING_AUDIT_UNAVAILABLE");
    }

    [Fact]
    public void Original_Mode_Threshold_And_Confidence_Remain_Intact()
    {
        var profile = new R379_AWSCloudTrailStopLoggingIndicatorRule().PrecisionProfile;
        Assert.Equal(1, profile.Threshold);
        Assert.Equal(82, profile.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
    }
}

public sealed class R380AdvancedAccuracyBatchTests
{
    private static Task<RuleEvaluationResult> Eval(TrafficRecord record)
        => new R380_AWSGuardDutyFindingExfilIndicatorRule().EvaluateAsync(NetworkBatch371380Context.At(record)).AsTask();

    // Six distinct regression invocations. No synthetic provider identity,
    // Info text, TLS metadata, or user-controlled query may imply an audit.
    [Theory]
    [InlineData("plausible")]
    [InlineData("descriptor-spoof")]
    [InlineData("tls-only")]
    [InlineData("wrong-host")]
    [InlineData("missing-source")]
    [InlineData("secret-query")]
    public async Task Missing_Trusted_Producer_Fails_Closed(string variation)
    {
        var record = NetworkBatch371380Context.Request("guardduty.us-east-1.amazonaws.com", "/findings", "GET");
        switch (variation)
        {
            case "descriptor-spoof":
                record.Info = "authenticated successful exfiltration confirmed by CloudTrail";
                break;
            case "tls-only":
                record.ApplicationProtocol = "TLS";
                break;
            case "wrong-host":
                record.HttpHost = "aws.example.attacker.invalid";
                break;
            case "missing-source":
                record.Source = null;
                break;
            case "secret-query":
                record.HttpUri = "/?token=synthetic-never-a-real-credential";
                break;
        }
        var result = await Eval(record);
        Assert.False(result.Matched);
        if (variation == "plausible")
            Assert.Contains(result.NoMatchReasons, x => x.Code == "GUARDDUTY_EXFIL_FINDING_AUDIT_UNAVAILABLE");
    }

    [Fact]
    public void Original_Mode_Threshold_And_Confidence_Remain_Intact()
    {
        var profile = new R380_AWSGuardDutyFindingExfilIndicatorRule().PrecisionProfile;
        Assert.Equal(1, profile.Threshold);
        Assert.Equal(82, profile.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
    }
}

public sealed class R375AdvancedAccuracyBatchTests
{
    private static Task<RuleEvaluationResult> Eval(TrafficRecord record)
        => new R375_AWSS3ListBucketsExternalRule()
            .EvaluateAsync(NetworkBatch371380Context.At(record)).AsTask();

    private static TrafficRecord Candidate()
        => NetworkBatch371380Context.Request("s3.amazonaws.com", "/", "GET");

    [Fact] public async Task Exact_ListBuckets_Request_Shape_Is_Eligible()
    {
        var result = await Eval(Candidate());
        Assert.True(result.Matched);
        Assert.Equal("R375", Assert.Single(result.Events).RuleId);
    }

    [Theory]
    [InlineData("list-objects")]
    [InlineData("bucket-specific")]
    [InlineData("spoofed-host")]
    [InlineData("tls-only")]
    [InlineData("missing-method")]
    [InlineData("udp")]
    [InlineData("absolute-url")]
    [InlineData("signed-query")]
    [InlineData("descriptor-spoof")]
    public async Task Unrelated_Or_Untrusted_Shape_Cannot_Prove_ListBuckets(string variation)
    {
        var record = Candidate();
        switch (variation)
        {
            case "list-objects": record.HttpUri = "/?list-type=2"; break;
            case "bucket-specific": record.HttpUri = "/example-bucket"; break;
            case "spoofed-host": record.HttpHost = "s3.amazonaws.com.attacker.invalid"; break;
            case "tls-only": record.ApplicationProtocol = "TLS"; break;
            case "missing-method": record.HttpMethod = null; break;
            case "udp": record.IsUdp = true; break;
            case "absolute-url": record.HttpUri = "http://s3.amazonaws.com/"; break;
            case "signed-query": record.HttpUri = "/?X-Amz-Credential=synthetic"; break;
            case "descriptor-spoof":
                record.HttpUri = "/not-listbuckets";
                record.Info = "AWS S3 ListBuckets authenticated success";
                break;
        }
        Assert.False((await Eval(record)).Matched);
    }

    [Fact] public void Existing_Policy_And_Threshold_Are_Unchanged()
    {
        var p = new R375_AWSS3ListBucketsExternalRule().PrecisionProfile;
        Assert.Equal(1, p.Threshold);
        Assert.Equal(82, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}

public sealed class R378AdvancedAccuracyBatchTests
{
    private static Task<RuleEvaluationResult> Eval(TrafficRecord record, int seconds = 0)
        => new R378_AWSLambdaInvokeBurstRule()
            .EvaluateAsync(NetworkBatch371380Context.At(record, seconds)).AsTask();

    private static TrafficRecord Candidate()
        => NetworkBatch371380Context.Request("lambda.us-east-1.amazonaws.com",
            "/2015-03-31/functions/my-function/invocations", "POST");

    [Fact] public async Task Four_Distinct_Requests_Required_For_Burst()
    {
        var seed = Candidate();
        for (var i = 0; i < 3; i++)
            Assert.False((await Eval(NetworkBatch371380Context.SameFlow(seed), i)).Matched);
        var result = await Eval(NetworkBatch371380Context.SameFlow(seed), 3);
        Assert.True(result.Matched);
        Assert.Equal("R378", Assert.Single(result.Events).RuleId);
    }

    [Fact] public async Task Duplicate_Packet_Id_Cannot_Fill_Burst()
    {
        var record = Candidate();
        await Eval(record);
        var result = await Eval(record, 1);
        Assert.Contains(result.NoMatchReasons, x => x.Code == "DEVOPS_BURST_DUPLICATE_PACKET");
    }

    [Fact] public async Task Out_Of_Order_Replay_Cannot_Fill_Burst()
    {
        var record = Candidate();
        await Eval(record, 10);
        var older = NetworkBatch371380Context.SameFlow(record);
        var result = await Eval(older, 9);
        Assert.Contains(result.NoMatchReasons, x => x.Code == "DEVOPS_BURST_OUT_OF_ORDER");
    }

    [Theory]
    [InlineData("wrong-method")]
    [InlineData("wrong-route")]
    [InlineData("spoofed-host")]
    [InlineData("tls-only")]
    [InlineData("signed-query")]
    [InlineData("absolute-url")]
    [InlineData("udp")]
    public async Task Unrelated_Or_Unsafe_Invocation_Cannot_Fill_Burst(string variation)
    {
        var record = Candidate();
        switch (variation)
        {
            case "wrong-method": record.HttpMethod = "GET"; break;
            case "wrong-route": record.HttpUri = "/2015-03-31/functions/my-function"; break;
            case "spoofed-host": record.HttpHost = "lambda.us-east-1.amazonaws.com.attacker.invalid"; break;
            case "tls-only": record.ApplicationProtocol = "TLS"; break;
            case "signed-query": record.HttpUri += "?X-Amz-Credential=synthetic"; break;
            case "absolute-url": record.HttpUri = "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/my-function/invocations"; break;
            case "udp": record.IsUdp = true; break;
        }
        Assert.False((await Eval(record)).Matched);
    }

    [Fact] public void Existing_Burst_Profile_Remains_Intact()
    {
        var p = new R378_AWSLambdaInvokeBurstRule().PrecisionProfile;
        Assert.Equal(4, p.Threshold);
        Assert.Equal(82, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
