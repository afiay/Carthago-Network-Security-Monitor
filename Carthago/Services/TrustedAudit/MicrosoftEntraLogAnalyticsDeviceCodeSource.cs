// SPDX-License-Identifier: MIT
// Authenticated Azure Monitor Logs source for R275 Entra observations.
// SOURCE CANDIDATE — UNVERIFIED. No credentials or workspace IDs are embedded.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;

namespace Carthago.Services.TrustedAudit
{
    /// <summary>
    /// Queries one operator-configured Log Analytics workspace through the
    /// Microsoft Entra-authenticated Azure Monitor Logs data-plane endpoint.
    ///
    /// The query text is fixed by CARTHAGO, not caller supplied. The adapter
    /// projects only the fields consumed by MicrosoftEntraDeviceCodeAuditIntake.
    /// A successful authenticated query establishes provider transport provenance
    /// only; it does not sign an R275 receipt or authorize an alert.
    /// </summary>
    public sealed class MicrosoftEntraLogAnalyticsDeviceCodeSource
    {
        internal const string TokenScope = "https://api.loganalytics.io/.default";
        internal const int MaxRows = 100;
        private const int MaxResponseBytes = 1024 * 1024;
        private static readonly Uri EndpointBase =
            new("https://api.loganalytics.azure.com/", UriKind.Absolute);

        private const string Query = @"SigninLogs
| where AuthenticationProtocol == ""deviceCode""
| where tostring(ResultType) == ""0""
| where RiskState == ""confirmedCompromised""
| where RiskDetail == ""adminConfirmedSigninCompromised""
| project Type=""SigninLogs"",
          Id=tostring(Id),
          CreatedDateTime=tostring(CreatedDateTime),
          AuthenticationProtocol=tostring(AuthenticationProtocol),
          ResultType=tostring(ResultType),
          RiskState=tostring(RiskState),
          RiskDetail=tostring(RiskDetail),
          IPAddress=tostring(IPAddress),
          UserId=tostring(UserId),
          AppId=tostring(AppId),
          ResourceId=tostring(ResourceId),
          HomeTenantId=tostring(HomeTenantId),
          ResourceTenantId=tostring(ResourceTenantId)
| order by CreatedDateTime desc
| take 100";

        private static readonly string[] ProjectionColumns =
        {
            "Type", "Id", "CreatedDateTime", "AuthenticationProtocol",
            "ResultType", "RiskState", "RiskDetail", "IPAddress",
            "UserId", "AppId", "ResourceId", "HomeTenantId", "ResourceTenantId"
        };

        private readonly TokenCredential _credential;
        private readonly HttpClient _http;
        private readonly Guid _workspaceId;

        public MicrosoftEntraLogAnalyticsDeviceCodeSource(
            TokenCredential credential,
            HttpClient httpClient,
            Guid workspaceId)
        {
            _credential = credential ?? throw new ArgumentNullException(nameof(credential));
            _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            if (workspaceId == Guid.Empty)
                throw new ArgumentException("A non-empty Log Analytics workspace ID is required.",
                    nameof(workspaceId));
            _workspaceId = workspaceId;
        }

        public async Task<(IReadOnlyList<MicrosoftEntraDeviceCodeAuditObservation> Observations, string Reason)>
            QueryRecentAsync(TimeSpan lookback, CancellationToken cancellationToken = default)
        {
            if (lookback < TimeSpan.FromMinutes(1) || lookback > TimeSpan.FromHours(1))
                return (Array.Empty<MicrosoftEntraDeviceCodeAuditObservation>(),
                    "INVALID_ENTRA_QUERY_LOOKBACK");

            AccessToken token;
            try
            {
                token = await _credential.GetTokenAsync(
                    new TokenRequestContext(new[] { TokenScope }),
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                return (Array.Empty<MicrosoftEntraDeviceCodeAuditObservation>(),
                    "ENTRA_LOG_ANALYTICS_TOKEN_UNAVAILABLE");
            }

            if (string.IsNullOrWhiteSpace(token.Token))
                return (Array.Empty<MicrosoftEntraDeviceCodeAuditObservation>(),
                    "ENTRA_LOG_ANALYTICS_TOKEN_UNAVAILABLE");

            var endpoint = new Uri(EndpointBase,
                $"v1/workspaces/{_workspaceId:D}/query");
            var requestBody = JsonSerializer.Serialize(new
            {
                query = Query,
                timespan = ToIso8601Duration(lookback)
            });

            using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
            request.Headers.TryAddWithoutValidation("Prefer", "wait=30");
            request.Content = new StringContent(requestBody, Encoding.UTF8, "application/json");

            HttpResponseMessage response;
            try
            {
                response = await _http.SendAsync(request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                return (Array.Empty<MicrosoftEntraDeviceCodeAuditObservation>(),
                    "ENTRA_LOG_ANALYTICS_REQUEST_FAILED");
            }

            using (response)
            {
                if (!response.IsSuccessStatusCode)
                    return (Array.Empty<MicrosoftEntraDeviceCodeAuditObservation>(),
                        MapStatus(response.StatusCode));

                if (response.Content.Headers.ContentLength is > MaxResponseBytes)
                    return (Array.Empty<MicrosoftEntraDeviceCodeAuditObservation>(),
                        "ENTRA_LOG_ANALYTICS_RESPONSE_TOO_LARGE");

                byte[] payload;
                try
                {
                    await response.Content.LoadIntoBufferAsync(MaxResponseBytes)
                        .ConfigureAwait(false);
                    payload = await response.Content.ReadAsByteArrayAsync(cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch
                {
                    return (Array.Empty<MicrosoftEntraDeviceCodeAuditObservation>(),
                        "ENTRA_LOG_ANALYTICS_RESPONSE_TOO_LARGE");
                }

                return ParseAuthenticatedResponse(payload);
            }
        }

        private static (IReadOnlyList<MicrosoftEntraDeviceCodeAuditObservation> Observations, string Reason)
            ParseAuthenticatedResponse(byte[] payload)
        {
            if (payload.Length == 0 || payload.Length > MaxResponseBytes)
                return (Array.Empty<MicrosoftEntraDeviceCodeAuditObservation>(),
                    "INVALID_ENTRA_LOG_ANALYTICS_RESPONSE");

            try
            {
                using var document = JsonDocument.Parse(payload, new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 6
                });

                if (document.RootElement.ValueKind != JsonValueKind.Object
                    || !document.RootElement.TryGetProperty("tables", out var tables)
                    || tables.ValueKind != JsonValueKind.Array)
                    return Empty("INVALID_ENTRA_LOG_ANALYTICS_RESPONSE");

                var tableItems = tables.EnumerateArray().ToArray();
                if (tableItems.Length != 1)
                    return Empty("INVALID_ENTRA_LOG_ANALYTICS_RESPONSE");

                var table = tableItems[0];
                if (!table.TryGetProperty("name", out var name)
                    || name.ValueKind != JsonValueKind.String
                    || !string.Equals(name.GetString(), "PrimaryResult", StringComparison.Ordinal)
                    || !table.TryGetProperty("columns", out var columns)
                    || columns.ValueKind != JsonValueKind.Array
                    || !table.TryGetProperty("rows", out var rows)
                    || rows.ValueKind != JsonValueKind.Array)
                    return Empty("INVALID_ENTRA_LOG_ANALYTICS_RESPONSE");

                var columnNames = new List<string>();
                foreach (var column in columns.EnumerateArray())
                {
                    if (column.ValueKind != JsonValueKind.Object
                        || !column.TryGetProperty("name", out var columnName)
                        || columnName.ValueKind != JsonValueKind.String)
                        return Empty("INVALID_ENTRA_LOG_ANALYTICS_SCHEMA");
                    columnNames.Add(columnName.GetString() ?? string.Empty);
                }

                if (columnNames.Count != ProjectionColumns.Length
                    || !columnNames.SequenceEqual(ProjectionColumns, StringComparer.Ordinal))
                    return Empty("INVALID_ENTRA_LOG_ANALYTICS_SCHEMA");

                var observations = new List<MicrosoftEntraDeviceCodeAuditObservation>();
                var count = 0;
                foreach (var row in rows.EnumerateArray())
                {
                    count++;
                    if (count > MaxRows || row.ValueKind != JsonValueKind.Array)
                        return Empty("INVALID_ENTRA_LOG_ANALYTICS_ROWS");

                    var cells = row.EnumerateArray().ToArray();
                    if (cells.Length != ProjectionColumns.Length)
                        return Empty("INVALID_ENTRA_LOG_ANALYTICS_ROWS");

                    var projection = new Dictionary<string, object?>(StringComparer.Ordinal);
                    for (var index = 0; index < ProjectionColumns.Length; index++)
                    {
                        if (cells[index].ValueKind != JsonValueKind.String)
                            return Empty("INVALID_ENTRA_LOG_ANALYTICS_ROWS");
                        projection[ProjectionColumns[index]] = cells[index].GetString();
                    }

                    var projectedJson = JsonSerializer.Serialize(projection);
                    if (!MicrosoftEntraDeviceCodeAuditIntake.TryInspectUntrustedProjectedJson(
                            projectedJson, out var untrusted, out _)
                        || untrusted == null)
                        return Empty("ENTRA_LOG_ANALYTICS_ROW_REJECTED");

                    observations.Add(new MicrosoftEntraDeviceCodeAuditObservation(
                        untrusted.OccurredAtUtc,
                        untrusted.SourceIp,
                        untrusted.ActorHash,
                        untrusted.ResourceHash,
                        untrusted.TraceHash,
                        fromTrustedProviderTransport: true));
                }

                return (observations, "AUTHENTICATED_ENTRA_LOG_ANALYTICS_QUERY");
            }
            catch (JsonException)
            {
                return Empty("INVALID_ENTRA_LOG_ANALYTICS_RESPONSE");
            }
        }

        private static (IReadOnlyList<MicrosoftEntraDeviceCodeAuditObservation> Observations, string Reason)
            Empty(string reason)
            => (Array.Empty<MicrosoftEntraDeviceCodeAuditObservation>(), reason);

        private static string MapStatus(HttpStatusCode status)
            => status switch
            {
                HttpStatusCode.Unauthorized => "ENTRA_LOG_ANALYTICS_UNAUTHORIZED",
                HttpStatusCode.Forbidden => "ENTRA_LOG_ANALYTICS_FORBIDDEN",
                (HttpStatusCode)429 => "ENTRA_LOG_ANALYTICS_THROTTLED",
                _ => "ENTRA_LOG_ANALYTICS_HTTP_ERROR"
            };

        private static string ToIso8601Duration(TimeSpan value)
        {
            if (value.TotalSeconds % 60 != 0)
                return XmlConvertDuration(value);
            return $"PT{(int)value.TotalMinutes}M";
        }

        private static string XmlConvertDuration(TimeSpan value)
            => System.Xml.XmlConvert.ToString(value);
    }
}
