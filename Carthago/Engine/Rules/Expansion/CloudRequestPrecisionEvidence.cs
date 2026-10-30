// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. HTTP request shape is not authenticated AWS identity,
// a successful API outcome, completed transfer, or authenticated cloud audit.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    internal static class CloudRequestPrecisionEvidence
    {
        internal static string? Reject(TrafficRecord record, DateTime timestampUtc, string ruleId)
        {
            // No credential/authentication, private namespace, AWS form body,
            // response-byte correlation, or authenticated audit producer exists.
            // Fail closed rather than infer outcomes from generic AWS vocabulary.
            var unavailable = ruleId switch
            {
                "R371" => "MAVEN_CREDENTIAL_PROVENANCE_UNAVAILABLE",
                "R372" => "DEPENDENCY_PRIVATE_NAMESPACE_PROVENANCE_UNAVAILABLE",
                "R373" => "STS_ASSUMEROLE_ACTION_PROVENANCE_UNAVAILABLE",
                "R374" => "AWS_ACCESS_KEY_URL_PRIVACY_PROVENANCE_UNAVAILABLE",
                "R376" => "S3_GETOBJECT_RESPONSE_BYTES_UNAVAILABLE",
                "R377" => "EC2_METADATA_LINK_LOCAL_BOUNDARY_GA_OPEN",
                "R379" => "CLOUDTRAIL_STOPLOGGING_AUDIT_UNAVAILABLE",
                "R380" => "GUARDDUTY_EXFIL_FINDING_AUDIT_UNAVAILABLE",
                _ => null
            };
            if (unavailable != null) return unavailable;
            if (ruleId is not ("R375" or "R378"))
                return "CLOUD_REQUEST_RULE_UNRECOGNIZED";

            if (!DevOpsHttpEvidence.HasParsedRequest(record))
                return "CLOUD_PARSED_HTTP_REQUIRED";

            // Client-supplied Host is not server identity. The parser does not
            // decrypt TLS. Reject non-origin targets, escapes and queries so
            // signed credentials cannot enter event path/evidence.
            var path = DevOpsHttpEvidence.OriginPath(record.HttpUri);
            if (path == null || record.HttpUri!.IndexOf('?') >= 0)
                return "CLOUD_SAFE_ORIGIN_TARGET_REQUIRED";

            if (ruleId == "R375")
            {
                // GET / on the service endpoint is ListBuckets request shape;
                // ?list-type=2 would be ListObjectsV2, not ListBuckets.
                return string.Equals(record.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase)
                    && string.Equals(record.HttpUri, "/", StringComparison.Ordinal)
                    && DevOpsHttpEvidence.HostMatches(record, "s3.amazonaws.com")
                    ? null : "S3_LISTBUCKETS_REQUEST_NOT_OBSERVED";
            }

            var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (!string.Equals(record.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase)
                || !IsRegionalLambdaHost(record.HttpHost)
                || parts.Length != 4
                || !string.Equals(parts[0], "2015-03-31", StringComparison.Ordinal)
                || !string.Equals(parts[1], "functions", StringComparison.Ordinal)
                || string.IsNullOrWhiteSpace(parts[2])
                || !string.Equals(parts[3], "invocations", StringComparison.OrdinalIgnoreCase))
                return "LAMBDA_INVOKE_REQUEST_NOT_OBSERVED";

            // Existing bounded per-record ID / monotonic time guard. The original
            // R378 4-in-10-minute threshold is still enforced by EvaluateSpec.
            return DevOpsRequestPrecisionEvidence.ObserveUnique(record, timestampUtc, ruleId);
        }

        private static bool IsRegionalLambdaHost(string? rawHost)
        {
            if (string.IsNullOrWhiteSpace(rawHost)) return false;
            var host = rawHost.Trim().TrimEnd('.');
            var colon = host.LastIndexOf(':');
            if (colon >= 0)
            {
                if (!int.TryParse(host[(colon + 1)..], out var port) || port is < 1 or > 65535)
                    return false;
                host = host[..colon];
            }
            const string prefix = "lambda.";
            const string suffix = ".amazonaws.com";
            if (!host.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                || !host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                return false;
            var region = host.Substring(prefix.Length, host.Length - prefix.Length - suffix.Length);
            if (region.Length < 4 || region.Length > 40
                || region[0] == '-' || region[^1] == '-') return false;
            foreach (var ch in region)
                if (!char.IsAsciiLetterOrDigit(ch) && ch != '-') return false;
            return true;
        }
    }
}
