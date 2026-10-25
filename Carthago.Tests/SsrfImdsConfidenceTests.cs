using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class SsrfImdsConfidenceTests
{
    [Fact]
    public async Task Metadata_Token_Header_Corroborates_Direct_Credential_Request()
    {
        var record = new TrafficRecord
        {
            Source = "10.0.0.20", Destination = "169.254.169.254", Protocol = "HTTP",
            DestinationPort = 80, ProcessName = "webapp.exe", HttpMethod = "GET",
            HttpHost = "169.254.169.254", HttpUri = "/latest/meta-data/iam/security-credentials",
            HttpRequestHeaders = "X-aws-ec2-metadata-token: replay-test-token"
        };

        var result = await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(
            new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UtcNow));

        Assert.True(result.Matched);
        Assert.True(result.Events.Single().ConfidenceScore >= 0.65);
    }

    [Fact]
    public async Task Metadata_Request_Without_Token_Stays_At_Base_Confidence()
    {
        var record = new TrafficRecord
        {
            Source = "10.0.0.21", Destination = "169.254.169.254", Protocol = "HTTP",
            DestinationPort = 80, ProcessName = "webapp.exe", HttpMethod = "GET",
            HttpHost = "169.254.169.254", HttpUri = "/latest/meta-data/iam/security-credentials"
        };

        var result = await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(
            new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UtcNow));

        Assert.True(result.Matched);
        Assert.True(result.Events.Single().ConfidenceScore < 0.65);
    }
}
