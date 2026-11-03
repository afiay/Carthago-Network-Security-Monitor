// SPDX-License-Identifier: MIT
// Microsoft Entra SigninLogs device-code parser. SOURCE CANDIDATE — UNVERIFIED.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Carthago.Services.TrustedAudit
{
    /// <summary>
    /// Privacy-minimized, UNSIGNED Microsoft Entra sign-in observation.
    /// Public JSON parsing never grants trusted-provider provenance.
    /// Raw user/app/resource identifiers are hashed before leaving the parser.
    /// </summary>
    public sealed class MicrosoftEntraDeviceCodeAuditObservation
    {
        internal MicrosoftEntraDeviceCodeAuditObservation(
            DateTimeOffset occurredAtUtc,
            string sourceIp,
            string actorHash,
            string resourceHash,
            string traceHash,
            bool fromTrustedProviderTransport)
        {
            OccurredAtUtc = occurredAtUtc;
            SourceIp = sourceIp;
            ActorHash = actorHash;
            ResourceHash = resourceHash;
            TraceHash = traceHash;
            FromTrustedProviderTransport = fromTrustedProviderTransport;
        }

        public DateTimeOffset OccurredAtUtc { get; }
        public string SourceIp { get; }
        public string ActorHash { get; }
        public string ResourceHash { get; }
        public string TraceHash { get; }
        public bool FromTrustedProviderTransport { get; }
    }

    /// <summary>
    /// Strict parser for a privacy-minimized Azure Monitor SigninLogs projection.
    /// It recognizes only successful device-code sign-ins explicitly marked by
    /// Entra as confirmed compromised through an administrator confirmation.
    ///
    /// The output is still UNSIGNED and UNTRUSTED. A future authenticated
    /// provider transport must independently establish source provenance before
    /// any signer can create a trusted R275 receipt.
    /// </summary>
    public static class MicrosoftEntraDeviceCodeAuditIntake
    {
        private const int MaxJsonChars = 16384;
        private static readonly UTF8Encoding Utf8 = new(false, true);
        private static readonly HashSet<string> RequiredFields = new(StringComparer.Ordinal)
        {
            "Type",
            "Id",
            "CreatedDateTime",
            "AuthenticationProtocol",
            "ResultType",
            "RiskState",
            "RiskDetail",
            "IPAddress",
            "UserId",
            "AppId",
            "ResourceId",
            "HomeTenantId",
            "ResourceTenantId"
        };

        public static bool TryInspectUntrustedProjectedJson(
            string? json,
            out MicrosoftEntraDeviceCodeAuditObservation? observation,
            out string reason)
        {
            observation = null;
            reason = "INVALID_ENTRA_SIGNIN_JSON";
            if (string.IsNullOrWhiteSpace(json) || json.Length > MaxJsonChars)
                return false;

            Dictionary<string, JsonElement> fields;
            try
            {
                using var document = JsonDocument.Parse(json, new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 2
                });
                if (document.RootElement.ValueKind != JsonValueKind.Object)
                    return false;

                fields = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
                foreach (var property in document.RootElement.EnumerateObject())
                {
                    if (!RequiredFields.Contains(property.Name)
                        || !fields.TryAdd(property.Name, property.Value.Clone()))
                    {
                        reason = "INVALID_ENTRA_SIGNIN_SCHEMA";
                        return false;
                    }
                }
            }
            catch (Exception ex) when (ex is JsonException or ArgumentException)
            {
                return false;
            }

            if (fields.Count != RequiredFields.Count)
            {
                reason = "INVALID_ENTRA_SIGNIN_SCHEMA";
                return false;
            }

            if (!ReadString(fields, "Type", out var type)
                || !string.Equals(type, "SigninLogs", StringComparison.Ordinal)
                || !ReadString(fields, "AuthenticationProtocol", out var protocol))
            {
                reason = "INVALID_ENTRA_SIGNIN_SCHEMA";
                return false;
            }

            if (!string.Equals(protocol, "deviceCode", StringComparison.Ordinal))
            {
                reason = "NOT_DEVICE_CODE_SIGNIN";
                return false;
            }

            if (!ReadString(fields, "ResultType", out var resultType)
                || !string.Equals(resultType, "0", StringComparison.Ordinal))
            {
                reason = "SIGNIN_NOT_SUCCESSFUL";
                return false;
            }

            if (!ReadString(fields, "RiskState", out var riskState)
                || !ReadString(fields, "RiskDetail", out var riskDetail)
                || !string.Equals(riskState, "confirmedCompromised", StringComparison.Ordinal)
                || !string.Equals(riskDetail, "adminConfirmedSigninCompromised", StringComparison.Ordinal))
            {
                reason = "COMPROMISE_NOT_ADMIN_CONFIRMED";
                return false;
            }

            if (!ReadString(fields, "IPAddress", out var sourceIp)
                || !IPAddress.TryParse(sourceIp, out var address)
                || IPAddress.IsLoopback(address)
                || address.Equals(IPAddress.Any)
                || address.Equals(IPAddress.IPv6Any)
                || address.Equals(IPAddress.None)
                || address.Equals(IPAddress.IPv6None))
            {
                reason = "INVALID_ENTRA_SOURCE_IP";
                return false;
            }

            if (!ReadString(fields, "CreatedDateTime", out var timestampText)
                || timestampText.IndexOf('T') < 0
                || !(timestampText.EndsWith("Z", StringComparison.Ordinal)
                    || timestampText.EndsWith("+00:00", StringComparison.Ordinal))
                || !DateTimeOffset.TryParse(timestampText, CultureInfo.InvariantCulture,
                    DateTimeStyles.None, out var occurredAtUtc)
                || occurredAtUtc.Offset != TimeSpan.Zero)
            {
                reason = "INVALID_ENTRA_TIMESTAMP";
                return false;
            }

            if (!ReadGuid(fields, "Id", out var signInId)
                || !ReadGuid(fields, "UserId", out var userId)
                || !ReadGuid(fields, "AppId", out var appId)
                || !ReadGuid(fields, "ResourceId", out var resourceId)
                || !ReadGuid(fields, "HomeTenantId", out var homeTenantId)
                || !ReadGuid(fields, "ResourceTenantId", out var resourceTenantId))
            {
                reason = "INVALID_ENTRA_SIGNIN_IDENTIFIERS";
                return false;
            }

            var actorHash = HashGuid(userId);
            var resourceHash = HashText(string.Join("\n",
                appId.ToString("N"),
                resourceId.ToString("N"),
                homeTenantId.ToString("N"),
                resourceTenantId.ToString("N")));
            var traceHash = HashGuid(signInId);

            observation = new MicrosoftEntraDeviceCodeAuditObservation(
                occurredAtUtc,
                address.ToString(),
                actorHash,
                resourceHash,
                traceHash,
                fromTrustedProviderTransport: false);
            reason = "UNTRUSTED_ENTRA_SIGNIN_CANDIDATE_ONLY";
            return true;
        }

        private static bool ReadString(
            Dictionary<string, JsonElement> fields,
            string key,
            out string value)
        {
            value = string.Empty;
            if (!fields.TryGetValue(key, out var element)
                || element.ValueKind != JsonValueKind.String)
                return false;
            value = element.GetString() ?? string.Empty;
            return value.Length is > 0 and <= 512;
        }

        private static bool ReadGuid(
            Dictionary<string, JsonElement> fields,
            string key,
            out Guid value)
        {
            value = Guid.Empty;
            return ReadString(fields, key, out var text)
                && Guid.TryParseExact(text, "D", out value)
                && value != Guid.Empty;
        }

        private static string HashGuid(Guid value)
            => HashText(value.ToString("N"));

        private static string HashText(string value)
            => Convert.ToHexString(SHA256.HashData(Utf8.GetBytes(value)))
                .ToLowerInvariant();
    }
}
