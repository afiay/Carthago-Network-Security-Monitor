// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Visible HTTP request shape is not cloud
// identity, authentication, successful secret listing, or tunnel creation.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    internal static class CloudProviderRequestEvidence
    {
        internal static string? Reject(TrafficRecord record, DateTime timestampUtc, string ruleId)
        {
            // Missing producers are intentionally distinct for each rule.
            // Never turn arbitrary Info, process names or client Host into audit.
            var missing = ruleId switch
            {
                "R381" => "AZURE_ARM_TOKEN_BODY_OR_AUDIT_UNAVAILABLE",
                "R383" => "AZURE_SAS_SAFE_QUERY_PROVENANCE_UNAVAILABLE",
                "R384" => "AZURE_IMDS_LINK_LOCAL_BOUNDARY_GA_OPEN",
                "R385" => "GCP_OAUTH_SCOPE_BODY_OR_AUDIT_UNAVAILABLE",
                "R386" => "GCP_SIGNED_URL_SAFE_QUERY_AND_RESPONSE_UNAVAILABLE",
                "R387" => "GCP_SERVICE_ACCOUNT_KEY_RESPONSE_UNAVAILABLE",
                "R389" => "NGROK_LOCAL_AGENT_AND_AUTH_PROVENANCE_UNAVAILABLE",
                "R390" => "TAILSCALE_TAILNET_AUTH_AUDIT_UNAVAILABLE",
                _ => null
            };
            if (missing != null) return missing;
            if (ruleId is not ("R382" or "R388"))
                return "CLOUD_PROVIDER_RULE_UNRECOGNIZED";
            if (!DevOpsHttpEvidence.HasParsedRequest(record))
                return "CLOUD_PROVIDER_PARSED_HTTP_REQUIRED";
            var path = DevOpsHttpEvidence.OriginPath(record.HttpUri);
            if (path == null)
                return "CLOUD_PROVIDER_SAFE_ORIGIN_REQUIRED";

            if (ruleId == "R382")
            {
                // Azure Key Vault List Secrets requires GET /secrets?api-version=...
                // on a vault-specific endpoint. This proves only a request shape.
                if (!string.Equals(record.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase)
                    || !string.Equals(path, "/secrets", StringComparison.Ordinal)
                    || !IsVaultHost(record.HttpHost)
                    || !HasSafeApiVersionOnly(record.HttpUri!))
                    return "KEYVAULT_LIST_SECRETS_REQUEST_NOT_OBSERVED";
                return DevOpsRequestPrecisionEvidence.ObserveUnique(record, timestampUtc, ruleId);
            }

            // Cloudflare Tunnel create is POST /client/v4/accounts/{id}/cfd_tunnel.
            // Authentication, response status and a running connector are unknown.
            if (!string.Equals(record.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase)
                || record.HttpUri!.IndexOf('?') >= 0
                || !DevOpsHttpEvidence.HostMatches(record, "api.cloudflare.com")
                || !IsCloudflareCreatePath(path))
                return "CLOUDFLARE_TUNNEL_CREATE_REQUEST_NOT_OBSERVED";
            return null;
        }

        private static bool IsVaultHost(string? host)
        {
            const string suffix = ".vault.azure.net";
            if (string.IsNullOrWhiteSpace(host) ||
                !host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                return false;
            var vaultName = host[..^suffix.Length];
            if (vaultName.Length is < 3 or > 63 ||
                vaultName[0] == '-' || vaultName[^1] == '-')
                return false;
            foreach (var ch in vaultName)
                if (!char.IsAsciiLetterOrDigit(ch) && ch != '-') return false;
            return true;
        }

        private static bool HasSafeApiVersionOnly(string target)
        {
            var q = target.IndexOf('?');
            if (q < 0 || q != target.LastIndexOf('?')) return false;
            var query = target[(q + 1)..];
            if (!query.StartsWith("api-version=", StringComparison.OrdinalIgnoreCase))
                return false;
            var version = query["api-version=".Length..];
            if (version.Length is < 3 or > 16) return false;
            var hasSeparator = false;
            foreach (var ch in version)
            {
                if (ch == '.' || ch == '-') hasSeparator = true;
                else if (!char.IsAsciiDigit(ch)) return false;
            }
            return hasSeparator && char.IsAsciiDigit(version[0]) &&
                char.IsAsciiDigit(version[^1]);
        }

        private static bool IsCloudflareCreatePath(string path)
        {
            var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 5 ||
                !string.Equals(parts[0], "client", StringComparison.Ordinal) ||
                !string.Equals(parts[1], "v4", StringComparison.Ordinal) ||
                !string.Equals(parts[2], "accounts", StringComparison.Ordinal) ||
                !string.Equals(parts[4], "cfd_tunnel", StringComparison.Ordinal) ||
                parts[3].Length != 32)
                return false;
            foreach (var ch in parts[3])
                if (!Uri.IsHexDigit(ch)) return false;
            return true;
        }
    }
}
