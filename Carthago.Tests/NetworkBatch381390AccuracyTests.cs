// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. All scenarios AUTHORED, UNEXECUTED.
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

internal static class NetworkBatch381390Context
{
    private static int _sequence;
    private static readonly DateTime Epoch = new(2026, 10, 30, 2, 0, 0, DateTimeKind.Utc);

    internal static TrafficRecord Request(string host, string path, string method = "GET")
    {
        var id = Interlocked.Increment(ref _sequence);
        return new TrafficRecord
        {
            Id = Guid.NewGuid(),
            Source = $"10.93.{id / 200}.{id % 200 + 1}",
            Destination = "8.8.8.8",
            IpVersion = 4, Protocol = "TCP", IsTcp = true, IsUdp = false,
            SourcePort = 50222, DestinationPort = 80,
            ApplicationProtocol = "HTTP", HttpMethod = method, HttpUri = path,
            HttpHost = host, Info = string.Empty
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

public sealed class CloudProvider381390UnavailableProvenanceTests
{
    // Eight rules with seven adversarial cases each: 56 authored invocations.
    // Each row has its own original severity/mode/threshold contract.
    private static readonly (string Id, string Reason, string Host, string Path, string Method, int Threshold)[] Rules =
    {
        ("R381", "AZURE_ARM_TOKEN_BODY_OR_AUDIT_UNAVAILABLE", "login.microsoftonline.com", "/common/oauth2/v2.0/token", "POST", 4),
        ("R383", "AZURE_SAS_SAFE_QUERY_PROVENANCE_UNAVAILABLE", "example.blob.core.windows.net", "/container/blob?sv=2025-01-01&sig=synthetic", "GET", 1),
        ("R384", "AZURE_IMDS_LINK_LOCAL_BOUNDARY_GA_OPEN", "169.254.169.254", "/metadata/identity/oauth2/token?resource=synthetic", "GET", 1),
        ("R385", "GCP_OAUTH_SCOPE_BODY_OR_AUDIT_UNAVAILABLE", "oauth2.googleapis.com", "/token", "POST", 1),
        ("R386", "GCP_SIGNED_URL_SAFE_QUERY_AND_RESPONSE_UNAVAILABLE", "storage.googleapis.com", "/bucket/object?X-Goog-Signature=synthetic", "GET", 4),
        ("R387", "GCP_SERVICE_ACCOUNT_KEY_RESPONSE_UNAVAILABLE", "iam.googleapis.com", "/v1/projects/-/serviceAccounts/example/keys", "GET", 1),
        ("R389", "NGROK_LOCAL_AGENT_AND_AUTH_PROVENANCE_UNAVAILABLE", "ngrok-free.app", "/api/tunnels", "POST", 1),
        ("R390", "TAILSCALE_TAILNET_AUTH_AUDIT_UNAVAILABLE", "login.tailscale.com", "/api/v2/tailnet", "POST", 1)
    };

    public static IEnumerable<object[]> BlockedCases()
    {
        foreach (var rule in Rules)
            foreach (var variation in new[]
            {
                "plausible", "descriptor-spoof", "tls-only", "wrong-host",
                "missing-source", "synthetic-secret-query", "fake-audit-header"
            })
                yield return new object[] { rule.Id, rule.Reason, rule.Host,
                    rule.Path, rule.Method, variation };
    }

    private static Task<RuleEvaluationResult> Eval(string id, TrafficRecord record)
    {
        var at = NetworkBatch381390Context.At(record);
        return id switch
        {
            "R381" => new R381_AzureARMTokenRequestBurstRule().EvaluateAsync(at).AsTask(),
            "R383" => new R383_AzureStorageSASTokenInURLRule().EvaluateAsync(at).AsTask(),
            "R384" => new R384_AzureIMDSTokenRequestRule().EvaluateAsync(at).AsTask(),
            "R385" => new R385_GCPOAuthScopeBroadRequestRule().EvaluateAsync(at).AsTask(),
            "R386" => new R386_GCPStorageSignedURLMassAccessRule().EvaluateAsync(at).AsTask(),
            "R387" => new R387_GCPServiceAccountKeyDownloadRule().EvaluateAsync(at).AsTask(),
            "R389" => new R389_NgrokTunnelCreationOrAuthRule().EvaluateAsync(at).AsTask(),
            "R390" => new R390_TailscaleTailnetAuthIndicatorRule().EvaluateAsync(at).AsTask(),
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };
    }

    [Theory]
    [MemberData(nameof(BlockedCases))]
    public async Task Missing_Trusted_Producer_Fails_Closed(
        string id, string reason, string host, string path, string method, string variation)
    {
        var record = NetworkBatch381390Context.Request(host, path, method);
        switch (variation)
        {
            case "descriptor-spoof":
                record.Info = "authenticated successful cloud operation proven by audit";
                break;
            case "tls-only":
                record.ApplicationProtocol = "TLS";
                record.HttpMethod = null;
                record.HttpUri = null;
                break;
            case "wrong-host":
                record.HttpHost = "example.attacker.invalid";
                break;
            case "missing-source":
                record.Source = null;
                break;
            case "synthetic-secret-query":
                record.HttpUri = "/?token=synthetic-never-a-real-credential";
                break;
            case "fake-audit-header":
                record.HttpRequestHeaders = "X-Cloud-Audit: successful";
                break;
        }
        var result = await Eval(id, record);
        Assert.False(result.Matched);
        Assert.Empty(result.Events);
        if (variation == "plausible")
            Assert.Contains(result.NoMatchReasons, x => x.Code == reason);
    }

    // Eight further invocations; no policy/profile relaxation.
    public static IEnumerable<object[]> ProfileCases()
    {
        foreach (var rule in Rules)
            yield return new object[] { rule.Id, rule.Threshold };
    }

    [Theory]
    [MemberData(nameof(ProfileCases))]
    public void Original_Alert_Profile_And_Threshold_Are_Preserved(string id, int threshold)
    {
        var profile = id switch
        {
            "R381" => new R381_AzureARMTokenRequestBurstRule().PrecisionProfile,
            "R383" => new R383_AzureStorageSASTokenInURLRule().PrecisionProfile,
            "R384" => new R384_AzureIMDSTokenRequestRule().PrecisionProfile,
            "R385" => new R385_GCPOAuthScopeBroadRequestRule().PrecisionProfile,
            "R386" => new R386_GCPStorageSignedURLMassAccessRule().PrecisionProfile,
            "R387" => new R387_GCPServiceAccountKeyDownloadRule().PrecisionProfile,
            "R389" => new R389_NgrokTunnelCreationOrAuthRule().PrecisionProfile,
            "R390" => new R390_TailscaleTailnetAuthIndicatorRule().PrecisionProfile,
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
        Assert.Equal(82, profile.MinimumConfidence);
        Assert.Equal(threshold, profile.Threshold);
    }
}

public sealed class R382KeyVaultListSecretsPrecisionTests
{
    private const string Host = "example-vault.vault.azure.net";
    private const string Target = "/secrets?api-version=7.4";

    private static Task<RuleEvaluationResult> Eval(TrafficRecord record, int seconds = 0)
        => new R382_AzureKeyVaultSecretEnumerationRule()
            .EvaluateAsync(NetworkBatch381390Context.At(record, seconds)).AsTask();

    private static TrafficRecord Candidate()
        => NetworkBatch381390Context.Request(Host, Target, "GET");

    [Fact]
    public async Task Four_Distinct_Requests_Are_Required_Not_Proven_Enumeration()
    {
        var seed = Candidate();
        for (var i = 0; i < 3; i++)
            Assert.False((await Eval(NetworkBatch381390Context.SameFlow(seed), i)).Matched);
        var result = await Eval(NetworkBatch381390Context.SameFlow(seed), 3);
        Assert.True(result.Matched);
        Assert.Equal("R382", Assert.Single(result.Events).RuleId);
    }

    [Fact]
    public async Task Duplicate_Packet_Cannot_Reach_Burst_Threshold()
    {
        var record = Candidate();
        await Eval(record, 0);
        var result = await Eval(record, 1);
        Assert.Contains(result.NoMatchReasons, x => x.Code == "DEVOPS_BURST_DUPLICATE_PACKET");
    }

    [Fact]
    public async Task Out_Of_Order_Replay_Is_Rejected()
    {
        var record = Candidate();
        await Eval(record, 10);
        var result = await Eval(NetworkBatch381390Context.SameFlow(record), 9);
        Assert.Contains(result.NoMatchReasons, x => x.Code == "DEVOPS_BURST_OUT_OF_ORDER");
    }

    [Theory]
    [InlineData("wrong-method")]
    [InlineData("single-secret")]
    [InlineData("wrong-host")]
    [InlineData("host-suffix-spoof")]
    [InlineData("tls-only")]
    [InlineData("udp")]
    [InlineData("absolute-target")]
    [InlineData("injected-query")]
    [InlineData("missing-version")]
    [InlineData("descriptor-spoof")]
    [InlineData("missing-source")]
    public async Task Benign_Malformed_Or_Untrusted_Request_Is_Not_Enumeration(string variation)
    {
        var record = Candidate();
        switch (variation)
        {
            case "wrong-method": record.HttpMethod = "POST"; break;
            case "single-secret": record.HttpUri = "/secrets/one?api-version=7.4"; break;
            case "wrong-host": record.HttpHost = "management.azure.com"; break;
            case "host-suffix-spoof": record.HttpHost = Host + ".attacker.invalid"; break;
            case "tls-only": record.ApplicationProtocol = "TLS"; break;
            case "udp": record.IsUdp = true; break;
            case "absolute-target": record.HttpUri = "http://" + Host + Target; break;
            case "injected-query": record.HttpUri += "&sig=synthetic"; break;
            case "missing-version": record.HttpUri = "/secrets"; break;
            case "descriptor-spoof":
                record.HttpUri = "/keys?api-version=7.4";
                record.Info = "successful secret enumeration";
                break;
            case "missing-source": record.Source = null; break;
        }
        Assert.False((await Eval(record)).Matched);
    }

    [Fact]
    public async Task Request_Evidence_Redacts_Vault_Host_And_Target()
    {
        var seed = Candidate();
        for (var i = 0; i < 3; i++)
            await Eval(NetworkBatch381390Context.SameFlow(seed), i);
        var evt = Assert.Single((await Eval(NetworkBatch381390Context.SameFlow(seed), 3)).Events);
        Assert.Equal("[REDACTED]", evt.DestinationHost);
        Assert.DoesNotContain(Host, evt.Evidence ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Target, evt.Evidence ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(evt.StructuredEvidence!.Items,
            item => item.Key == "http.path" && item.Value == "[REDACTED]");
    }

    [Fact]
    public void Original_Profile_Remains_Unchanged()
    {
        var p = new R382_AzureKeyVaultSecretEnumerationRule().PrecisionProfile;
        Assert.Equal(4, p.Threshold);
        Assert.Equal(82, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}

public sealed class R388CloudflareTunnelCreatePrecisionTests
{
    private const string AccountId = "0123456789abcdef0123456789abcdef";
    private const string Target = "/client/v4/accounts/" + AccountId + "/cfd_tunnel";

    private static Task<RuleEvaluationResult> Eval(TrafficRecord record)
        => new R388_CloudflareTunnelCreationIndicatorRule()
            .EvaluateAsync(NetworkBatch381390Context.At(record)).AsTask();

    private static TrafficRecord Candidate()
        => NetworkBatch381390Context.Request("api.cloudflare.com", Target, "POST");

    [Fact]
    public async Task Exact_Create_Request_Shape_Is_Eligible_Not_Proven_Creation()
    {
        var result = await Eval(Candidate());
        Assert.True(result.Matched);
        Assert.Equal("R388", Assert.Single(result.Events).RuleId);
    }

    [Theory]
    [InlineData("get-list")]
    [InlineData("wrong-route")]
    [InlineData("wrong-host")]
    [InlineData("host-suffix-spoof")]
    [InlineData("tls-only")]
    [InlineData("udp")]
    [InlineData("absolute-target")]
    [InlineData("secret-query")]
    [InlineData("invalid-account")]
    [InlineData("descriptor-spoof")]
    [InlineData("missing-source")]
    public async Task Benign_Or_Untrusted_Request_Cannot_Prove_Tunnel_Creation(string variation)
    {
        var record = Candidate();
        switch (variation)
        {
            case "get-list": record.HttpMethod = "GET"; break;
            case "wrong-route": record.HttpUri = "/client/v4/accounts/" + AccountId + "/cfd_tunnel/one"; break;
            case "wrong-host": record.HttpHost = "trycloudflare.com"; break;
            case "host-suffix-spoof": record.HttpHost = "api.cloudflare.com.attacker.invalid"; break;
            case "tls-only": record.ApplicationProtocol = "TLS"; break;
            case "udp": record.IsUdp = true; break;
            case "absolute-target": record.HttpUri = "https://api.cloudflare.com" + Target; break;
            case "secret-query": record.HttpUri += "?token=synthetic"; break;
            case "invalid-account": record.HttpUri = "/client/v4/accounts/short/cfd_tunnel"; break;
            case "descriptor-spoof":
                record.HttpUri = "/client/v4/accounts/" + AccountId + "/tunnels";
                record.Info = "Cloudflare tunnel created authenticated";
                break;
            case "missing-source": record.Source = null; break;
        }
        Assert.False((await Eval(record)).Matched);
    }

    [Fact]
    public async Task Create_Request_Evidence_Redacts_Account_Path()
    {
        var evt = Assert.Single((await Eval(Candidate())).Events);
        Assert.Equal("[REDACTED]", evt.DestinationHost);
        Assert.DoesNotContain(AccountId, evt.Evidence ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(evt.StructuredEvidence!.Items,
            item => item.Key == "http.path" && item.Value == "[REDACTED]");
    }

    [Fact]
    public void Original_Profile_Remains_Unchanged()
    {
        var p = new R388_CloudflareTunnelCreationIndicatorRule().PrecisionProfile;
        Assert.Equal(1, p.Threshold);
        Assert.Equal(82, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
