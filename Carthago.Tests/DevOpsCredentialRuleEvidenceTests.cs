// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// Provider-token rule boundaries must be based on observed tokens, not generic
/// HTTP/metadata context or names such as "credential" and "token".
/// </summary>
public sealed class DevOpsCredentialRuleEvidenceTests
{
    [Fact]
    public async Task Routine_Cloud_Init_Credential_Request_Must_Not_Match_Unrelated_Devops_Secrets()
    {
        var record = Record(
            "169.254.169.254",
            "/latest/meta-data/iam/security-credentials/synthetic-role",
            "cloud-init bootstrap metadata credential token headers; no observed PAT");
        record.Destination = "169.254.169.254";
        record.ProcessName = "/usr/bin/cloud-init";
        record.HttpRequestHeaders = "Host: 169.254.169.254\r\nX-aws-ec2-metadata-token: [REDACTED]";

        Assert.False((await new R353_GitHubPersonalAccessTokenInTrafficRule()
            .EvaluateAsync(Context(record))).Matched);
        Assert.False((await new R354_GitLabPrivateTokenInTrafficRule()
            .EvaluateAsync(Context(record))).Matched);
        Assert.False((await new R359_AzureDevOpsPATInURLRule()
            .EvaluateAsync(Context(record))).Matched);
    }

    [Fact]
    public async Task GitHub_Token_Must_Be_Observed_Not_Inferred_From_Vocabulary()
    {
        var benign = Record("api.github.com", "/repos/example/repo",
            "GitHub authorization token personal access token documentation");
        Assert.False((await new R353_GitHubPersonalAccessTokenInTrafficRule()
            .EvaluateAsync(Context(benign))).Matched);

        benign.Info = "Synthetic GitHub PAT candidate ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
        Assert.True((await new R353_GitHubPersonalAccessTokenInTrafficRule()
            .EvaluateAsync(Context(benign))).Matched);
    }

    [Fact]
    public async Task GitLab_Token_Must_Be_Observed_Not_Inferred_From_Vocabulary()
    {
        var benign = Record("gitlab.com", "/api/v4/projects",
            "GitLab private-token authorization documentation");
        Assert.False((await new R354_GitLabPrivateTokenInTrafficRule()
            .EvaluateAsync(Context(benign))).Matched);

        benign.Info = "Synthetic GitLab PAT candidate glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
        Assert.True((await new R354_GitLabPrivateTokenInTrafficRule()
            .EvaluateAsync(Context(benign))).Matched);
    }

    [Fact]
    public async Task Azure_Devops_Pat_Must_Appear_In_The_Request_Url()
    {
        var benign = Record("dev.azure.com", "/example/_apis/projects",
            "azure devops personal access token PAT token documentation");
        Assert.False((await new R359_AzureDevOpsPATInURLRule()
            .EvaluateAsync(Context(benign))).Matched);

        // A token-shaped string in an unrelated diagnostic field is not a PAT in URL.
        benign.Info = "azure devops PAT " + new string('A', 52);
        Assert.False((await new R359_AzureDevOpsPATInURLRule()
            .EvaluateAsync(Context(benign))).Matched);

        var syntheticToken = new string('A', 52);
        benign.HttpUri = "/example/_apis/projects?pat=" + syntheticToken;
        var result = await new R359_AzureDevOpsPATInURLRule()
            .EvaluateAsync(Context(benign));
        Assert.True(result.Matched);

        // The URL query is inspection input, never materialized in
        // structured/legacy evidence or detection summaries.
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain(syntheticToken, evt.Evidence ?? string.Empty);
        Assert.DoesNotContain(syntheticToken, evt.Summary ?? string.Empty);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, item =>
            item.Value.Contains(syntheticToken, StringComparison.Ordinal));
    }

    private static TrafficRecord Record(string host, string uri, string info)
        => new()
        {
            Source = "10.2.0.12",
            Destination = "198.51.100.22",
            DestinationPort = 80,
            Protocol = "HTTP",
            ApplicationProtocol = "HTTP",
            HttpMethod = "GET",
            HttpHost = host,
            HttpUri = uri,
            ProcessName = "diagnostic-client.exe",
            Info = info
        };

    private static RuleEvaluationContext Context(TrafficRecord record)
        => new(record, Sensitivity.Balanced, new DateTime(2026, 10, 26, 13, 0, 0, DateTimeKind.Utc));
}
