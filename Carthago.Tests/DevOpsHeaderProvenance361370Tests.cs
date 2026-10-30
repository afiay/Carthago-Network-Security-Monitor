// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. Parser/privacy regression facts; no execution yet.
using System;
using System.Text;
using System.Text.Json;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public sealed class DevOpsHeaderProvenance361370Tests
{
    private static HttpLight.HttpInfo Parse(string request)
    {
        Assert.True(HttpLight.TryParseHttp(Encoding.ASCII.GetBytes(request), out var parsed));
        return parsed;
    }

    [Theory]
    [InlineData("hvs.")]
    [InlineData("hvb.")]
    [InlineData("s.")]
    public void Vault_Header_Pattern_Is_Observed_Without_Retaining_Secret(string prefix)
    {
        var secret = prefix + new string('A', 28);
        var p = Parse($"GET /v1/secret/data/test HTTP/1.1\r\nHost: vault.internal\r\nX-Vault-Token: {secret}\r\n\r\n");
        Assert.True(p.ObservedVaultTokenPattern);
        Assert.Contains("X-Vault-Token: [REDACTED]", p.JoinedHeaderLines);
        Assert.DoesNotContain(secret, p.JoinedHeaderLines);
    }

    [Fact] public void Duplicate_Vault_Headers_Fail_Closed_And_Are_Redacted()
    {
        var secret = "hvs." + new string('A', 28);
        var p = Parse($"GET /v1/secret HTTP/1.1\r\nHost: vault.internal\r\nX-Vault-Token: {secret}\r\nX-Vault-Token: {secret}\r\n\r\n");
        Assert.False(p.ObservedVaultTokenPattern);
        Assert.DoesNotContain(secret, p.JoinedHeaderLines);
    }

    [Fact] public void Incomplete_Vault_Header_Block_Does_Not_Assert_Token()
    {
        var secret = "hvs." + new string('A', 28);
        var p = Parse($"GET /v1/secret HTTP/1.1\r\nHost: vault.internal\r\nX-Vault-Token: {secret}\r\n");
        Assert.False(p.ObservedVaultTokenPattern);
        Assert.DoesNotContain(secret, p.JoinedHeaderLines);
    }

    [Fact] public void Terraform_Bearer_Is_Classified_And_Redacted()
    {
        var secret = "atlasv1." + new string('A', 28);
        var p = Parse($"GET /api/v2/organizations HTTP/1.1\r\nHost: app.terraform.io\r\nAuthorization: Bearer {secret}\r\n\r\n");
        Assert.True(p.ObservedTerraformTokenPattern);
        Assert.DoesNotContain(secret, p.JoinedHeaderLines);
    }

    [Fact] public void Npm_Bearer_Is_Classified_And_Redacted()
    {
        var secret = "npm_" + new string('A', 28);
        var p = Parse($"GET /example HTTP/1.1\r\nHost: registry.npmjs.org\r\nAuthorization: Bearer {secret}\r\n\r\n");
        Assert.True(p.ObservedNpmTokenPattern);
        Assert.DoesNotContain(secret, p.JoinedHeaderLines);
    }

    [Fact] public void Duplicate_Authorization_Cannot_Assert_Terraform_Or_Npm()
    {
        var secret = "npm_" + new string('A', 28);
        var p = Parse($"GET /example HTTP/1.1\r\nHost: registry.npmjs.org\r\nAuthorization: Bearer {secret}\r\nAuthorization: Bearer {secret}\r\n\r\n");
        Assert.False(p.ObservedNpmTokenPattern);
        Assert.DoesNotContain(secret, p.JoinedHeaderLines);
    }

    [Fact] public void Aws_ListSecrets_Requires_Exact_Complete_Header()
    {
        var p = Parse("POST / HTTP/1.1\r\nHost: secretsmanager.us-east-1.amazonaws.com\r\nX-Amz-Target: secretsmanager.ListSecrets\r\n\r\n");
        Assert.True(p.ObservedAwsListSecretsRequest);
        var incomplete = Parse("POST / HTTP/1.1\r\nHost: secretsmanager.us-east-1.amazonaws.com\r\nX-Amz-Target: secretsmanager.ListSecrets\r\n");
        Assert.False(incomplete.ObservedAwsListSecretsRequest);
    }

    [Fact] public void Aws_Duplicate_Target_Is_Ambiguous()
    {
        var p = Parse("POST / HTTP/1.1\r\nHost: secretsmanager.us-east-1.amazonaws.com\r\nX-Amz-Target: secretsmanager.ListSecrets\r\nX-Amz-Target: secretsmanager.ListSecrets\r\n\r\n");
        Assert.False(p.ObservedAwsListSecretsRequest);
    }

    [Fact] public void PyPi_Basic_Auth_Is_Classified_And_Redacted()
    {
        var secret = "dXNlcjpwYXNzd29yZA==";
        var p = Parse($"POST /legacy/ HTTP/1.1\r\nHost: upload.pypi.org\r\nAuthorization: Basic {secret}\r\n\r\n");
        Assert.True(p.ObservedPyPiUploadAuthorization);
        Assert.DoesNotContain(secret, p.JoinedHeaderLines);
    }

    [Fact] public void Incomplete_Authorization_Is_Not_PyPi_Provenance()
    {
        var p = Parse("POST /legacy/ HTTP/1.1\r\nHost: upload.pypi.org\r\nAuthorization: Basic dXNlcjpwYXNzd29yZA==\r\n");
        Assert.False(p.ObservedPyPiUploadAuthorization);
    }

    [Fact] public void Imported_Json_Cannot_Assert_New_Parser_Only_Flags()
    {
        var record = JsonSerializer.Deserialize<TrafficRecord>("{\"HttpVaultTokenPatternObserved\":true,\"HttpTerraformTokenPatternObserved\":true,\"HttpNpmTokenPatternObserved\":true,\"HttpPyPiUploadAuthorizationObserved\":true,\"HttpAwsListSecretsRequestObserved\":true}");
        Assert.NotNull(record);
        Assert.False(record!.HttpVaultTokenPatternObserved);
        Assert.False(record.HttpTerraformTokenPatternObserved);
        Assert.False(record.HttpNpmTokenPatternObserved);
        Assert.False(record.HttpPyPiUploadAuthorizationObserved);
        Assert.False(record.HttpAwsListSecretsRequestObserved);
    }
}
