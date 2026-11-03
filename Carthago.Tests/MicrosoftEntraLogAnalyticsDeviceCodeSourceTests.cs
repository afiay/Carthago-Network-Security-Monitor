// SPDX-License-Identifier: MIT
// Authenticated Azure Monitor Logs source tests for R275. SOURCE CANDIDATE — UNVERIFIED.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Carthago.Services.TrustedAudit;
using Xunit;

namespace Carthago.Tests;

public sealed class MicrosoftEntraLogAnalyticsDeviceCodeSourceTests
{
    private static readonly Guid Workspace =
        Guid.Parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");

    private sealed class FixedCredential : TokenCredential
    {
        public List<string[]> RequestedScopes { get; } = new();

        public override AccessToken GetToken(
            TokenRequestContext requestContext,
            CancellationToken cancellationToken)
        {
            RequestedScopes.Add(requestContext.Scopes);
            return new AccessToken("test-token", DateTimeOffset.UtcNow.AddHours(1));
        }

        public override ValueTask<AccessToken> GetTokenAsync(
            TokenRequestContext requestContext,
            CancellationToken cancellationToken)
        {
            RequestedScopes.Add(requestContext.Scopes);
            return ValueTask.FromResult(
                new AccessToken("test-token", DateTimeOffset.UtcNow.AddHours(1)));
        }
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _response;

        public RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> response)
            => _response = response;

        public HttpMethod? Method { get; private set; }
        public Uri? Uri { get; private set; }
        public string? Authorization { get; private set; }
        public string? Prefer { get; private set; }
        public string? Body { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Method = request.Method;
            Uri = request.RequestUri;
            Authorization = request.Headers.Authorization?.ToString();
            Prefer = request.Headers.TryGetValues("Prefer", out var values)
                ? values.SingleOrDefault()
                : null;
            Body = request.Content == null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return _response(request);
        }
    }

    private static string Response(params object[][] rows)
    {
        var names = new[]
        {
            "Type", "Id", "CreatedDateTime", "AuthenticationProtocol",
            "ResultType", "RiskState", "RiskDetail", "IPAddress",
            "UserId", "AppId", "ResourceId", "HomeTenantId", "ResourceTenantId"
        };
        var response = new
        {
            tables = new[]
            {
                new
                {
                    name = "PrimaryResult",
                    columns = names.Select(name => new { name, type = "string" }),
                    rows
                }
            }
        };
        return JsonSerializer.Serialize(response);
    }

    private static object[] ValidRow() => new object[]
    {
        "SigninLogs",
        "11111111-1111-4111-8111-111111111111",
        "2026-11-03T20:00:00.0000000+00:00",
        "deviceCode",
        "0",
        "confirmedCompromised",
        "adminConfirmedSigninCompromised",
        "203.0.113.25",
        "22222222-2222-4222-8222-222222222222",
        "33333333-3333-4333-8333-333333333333",
        "44444444-4444-4444-8444-444444444444",
        "55555555-5555-4555-8555-555555555555",
        "66666666-6666-4666-8666-666666666666"
    };

    [Fact]
    public async Task Authenticated_Query_Uses_Fixed_Endpoint_Scope_Kql_And_Minimized_Result()
    {
        var credential = new FixedCredential();
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(Response(ValidRow()), Encoding.UTF8, "application/json")
        });
        using var http = new HttpClient(handler);
        var source = new MicrosoftEntraLogAnalyticsDeviceCodeSource(
            credential, http, Workspace);

        var result = await source.QueryRecentAsync(TimeSpan.FromMinutes(10));

        Assert.Equal("AUTHENTICATED_ENTRA_LOG_ANALYTICS_QUERY", result.Reason);
        var observation = Assert.Single(result.Observations);
        Assert.True(observation.FromTrustedProviderTransport);
        Assert.Equal("203.0.113.25", observation.SourceIp);
        Assert.Equal(64, observation.ActorHash.Length);
        Assert.Equal(64, observation.ResourceHash.Length);
        Assert.Equal(64, observation.TraceHash.Length);

        Assert.Single(credential.RequestedScopes);
        Assert.Equal(
            MicrosoftEntraLogAnalyticsDeviceCodeSource.TokenScope,
            Assert.Single(credential.RequestedScopes[0]));
        Assert.Equal(HttpMethod.Post, handler.Method);
        Assert.Equal(
            $"https://api.loganalytics.azure.com/v1/workspaces/{Workspace:D}/query",
            handler.Uri?.ToString());
        Assert.Equal("Bearer test-token", handler.Authorization);
        Assert.Equal("wait=30", handler.Prefer);
        Assert.NotNull(handler.Body);
        Assert.Contains("SigninLogs", handler.Body, StringComparison.Ordinal);
        Assert.Contains("AuthenticationProtocol", handler.Body, StringComparison.Ordinal);
        Assert.Contains("confirmedCompromised", handler.Body, StringComparison.Ordinal);
        Assert.Contains("PT10M", handler.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("UserPrincipalName", handler.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("AuthenticationDetails", handler.Body, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(61)]
    public async Task Invalid_Lookback_Does_Not_Request_A_Token_Or_Network(int minutes)
    {
        var credential = new FixedCredential();
        var handler = new RecordingHandler(_ => throw new InvalidOperationException());
        using var http = new HttpClient(handler);
        var source = new MicrosoftEntraLogAnalyticsDeviceCodeSource(
            credential, http, Workspace);

        var result = await source.QueryRecentAsync(TimeSpan.FromMinutes(minutes));

        Assert.Equal("INVALID_ENTRA_QUERY_LOOKBACK", result.Reason);
        Assert.Empty(result.Observations);
        Assert.Empty(credential.RequestedScopes);
        Assert.Null(handler.Method);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, "ENTRA_LOG_ANALYTICS_UNAUTHORIZED")]
    [InlineData(HttpStatusCode.Forbidden, "ENTRA_LOG_ANALYTICS_FORBIDDEN")]
    [InlineData((HttpStatusCode)429, "ENTRA_LOG_ANALYTICS_THROTTLED")]
    [InlineData(HttpStatusCode.InternalServerError, "ENTRA_LOG_ANALYTICS_HTTP_ERROR")]
    public async Task Http_Failures_Are_Sanitized(
        HttpStatusCode status, string expected)
    {
        var credential = new FixedCredential();
        var handler = new RecordingHandler(_ => new HttpResponseMessage(status));
        using var http = new HttpClient(handler);
        var source = new MicrosoftEntraLogAnalyticsDeviceCodeSource(
            credential, http, Workspace);

        var result = await source.QueryRecentAsync(TimeSpan.FromMinutes(5));

        Assert.Equal(expected, result.Reason);
        Assert.Empty(result.Observations);
    }

    [Fact]
    public async Task Unexpected_Response_Schema_Is_Rejected()
    {
        var malformed = JsonSerializer.Serialize(new
        {
            tables = new[]
            {
                new
                {
                    name = "PrimaryResult",
                    columns = new[] { new { name = "UserPrincipalName", type = "string" } },
                    rows = new[] { new object[] { "sensitive@example.test" } }
                }
            }
        });
        var credential = new FixedCredential();
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(malformed, Encoding.UTF8, "application/json")
        });
        using var http = new HttpClient(handler);
        var source = new MicrosoftEntraLogAnalyticsDeviceCodeSource(
            credential, http, Workspace);

        var result = await source.QueryRecentAsync(TimeSpan.FromMinutes(5));

        Assert.Equal("INVALID_ENTRA_LOG_ANALYTICS_SCHEMA", result.Reason);
        Assert.Empty(result.Observations);
    }

    [Fact]
    public async Task Provider_Row_That_Fails_Strict_Signin_Parser_Is_Rejected()
    {
        var row = ValidRow();
        row[4] = "50126";
        var credential = new FixedCredential();
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(Response(row), Encoding.UTF8, "application/json")
        });
        using var http = new HttpClient(handler);
        var source = new MicrosoftEntraLogAnalyticsDeviceCodeSource(
            credential, http, Workspace);

        var result = await source.QueryRecentAsync(TimeSpan.FromMinutes(5));

        Assert.Equal("ENTRA_LOG_ANALYTICS_ROW_REJECTED", result.Reason);
        Assert.Empty(result.Observations);
    }

    [Fact]
    public void Empty_Workspace_Id_Is_Rejected_Before_Any_Query()
    {
        using var http = new HttpClient(new RecordingHandler(
            _ => new HttpResponseMessage(HttpStatusCode.OK)));
        Assert.Throws<ArgumentException>(() =>
            new MicrosoftEntraLogAnalyticsDeviceCodeSource(
                new FixedCredential(), http, Guid.Empty));
    }
}
