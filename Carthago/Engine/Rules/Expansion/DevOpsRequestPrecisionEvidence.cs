// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. Request shape is not server identity, authenticated
// runner activity, token issuance, successful download, or API operation outcome.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    internal static class DevOpsRequestPrecisionEvidence
    {
        private sealed class SeenWindow
        {
            internal readonly List<(Guid Id, DateTime At)> Observations = new();
            internal DateTime Latest = DateTime.MinValue;
        }
        private static readonly ConcurrentDictionary<string, SeenWindow> Windows = new(StringComparer.Ordinal);
        private const int MaxKeys = 16384;
        private const int MaxObservations = 512;

        internal static string? Reject(TrafficRecord r, DateTime at, string ruleId)
        {
            // OIDC request URLs are supplied dynamically by the GitHub runner.
            // No authenticated runner/audit producer is connected.
            if (ruleId == "R361") return "GITHUB_OIDC_RUNNER_AUDIT_UNAVAILABLE";
            if (!DevOpsHttpEvidence.HasParsedRequest(r)) return "DEVOPS_PARSED_HTTP_REQUIRED";
            var path = DevOpsHttpEvidence.OriginPath(r.HttpUri);
            if (path == null) return "DEVOPS_ORIGIN_TARGET_REQUIRED";
            var method = r.HttpMethod ?? string.Empty;
            var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            bool Is(string expected) => string.Equals(method, expected, StringComparison.OrdinalIgnoreCase);
            bool Seg(int index, string value) => index < parts.Length && string.Equals(parts[index], value, StringComparison.OrdinalIgnoreCase);
            string? reason = ruleId switch
            {
                "R362" => Is("POST") && DevOpsHttpEvidence.HostMatches(r, "api.github.com")
                    && ((parts.Length == 6 && Seg(0, "repos") && Seg(3, "actions") && Seg(4, "runners") && Seg(5, "registration-token"))
                        || (parts.Length == 5 && Seg(0, "orgs") && Seg(2, "actions") && Seg(3, "runners") && Seg(4, "registration-token")))
                    ? null : "GITHUB_RUNNER_REGISTRATION_REQUEST_NOT_OBSERVED",
                "R363" => Is("GET") && DevOpsHttpEvidence.HostMatches(r, "api.github.com")
                    && parts.Length == 7 && Seg(0, "repos") && Seg(3, "actions") && Seg(4, "artifacts") && Seg(6, "zip")
                    ? null : "CI_ARTIFACT_ARCHIVE_REQUEST_NOT_OBSERVED",
                "R364" => Is("POST") && path.Length == 0 && IsAwsSecretsManagerHost(r.HttpHost)
                    && r.HttpAwsListSecretsRequestObserved
                    ? null : "AWS_LISTSECRETS_REQUEST_NOT_OBSERVED",
                "R365" => path.StartsWith("/v1/", StringComparison.OrdinalIgnoreCase) && r.HttpVaultTokenPatternObserved
                    ? null : "VAULT_TOKEN_HEADER_NOT_OBSERVED",
                "R366" => Is("POST") && parts.Length == 4 && Seg(0, "v1") && Seg(1, "transit")
                    && Seg(2, "decrypt") && !string.IsNullOrWhiteSpace(parts[3])
                    ? null : "VAULT_TRANSIT_DECRYPT_REQUEST_NOT_OBSERVED",
                "R367" => DevOpsHttpEvidence.HostMatches(r, "app.terraform.io") && r.HttpTerraformTokenPatternObserved
                    ? null : "TERRAFORM_TOKEN_HEADER_NOT_OBSERVED",
                "R368" => Is("GET") && DevOpsHttpEvidence.HostMatches(r, "registry-1.docker.io") && IsDockerArtifact(parts)
                    ? null : "DOCKER_REGISTRY_ARTIFACT_REQUEST_NOT_OBSERVED",
                "R369" => DevOpsHttpEvidence.HostMatches(r, "registry.npmjs.org") && r.HttpNpmTokenPatternObserved
                    ? null : "NPM_TOKEN_HEADER_NOT_OBSERVED",
                "R370" => Is("POST") && path == "/legacy" && DevOpsHttpEvidence.HostMatches(r, "upload.pypi.org")
                    && r.HttpPyPiUploadAuthorizationObserved
                    ? null : "PYPI_AUTHENTICATED_UPLOAD_REQUEST_NOT_OBSERVED",
                _ => "UNRECOGNIZED_DEVOPS_RULE"
            };
            if (reason != null) return reason;
            // Duplicate captured records and out-of-order replay cannot fill bursts.
            if (ruleId is "R363" or "R364" or "R366" or "R368")
                return ObserveUnique(r, at, ruleId);
            return null;
        }

        private static bool IsAwsSecretsManagerHost(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return false;
            var host = raw.Trim().TrimEnd('.');
            return host.StartsWith("secretsmanager.", StringComparison.OrdinalIgnoreCase)
                && (host.EndsWith(".amazonaws.com", StringComparison.OrdinalIgnoreCase)
                    || host.EndsWith(".amazonaws.com.cn", StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsDockerArtifact(string[] parts)
        {
            if (parts.Length < 5 || !string.Equals(parts[0], "v2", StringComparison.OrdinalIgnoreCase))
                return false;
            for (var i = 2; i < parts.Length - 1; i++)
                if (string.Equals(parts[i], "manifests", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(parts[i], "blobs", StringComparison.OrdinalIgnoreCase))
                    return !string.IsNullOrWhiteSpace(parts[i + 1]);
            return false;
        }

        private static string? ObserveUnique(TrafficRecord r, DateTime at, string id)
        {
            if (r.Id == Guid.Empty || string.IsNullOrWhiteSpace(r.Source) || string.IsNullOrWhiteSpace(r.Destination))
                return "DEVOPS_BURST_ATTRIBUTION_MISSING";
            var key = string.Join("|", id, r.Source, r.Destination, r.HttpHost);
            if (!Windows.TryGetValue(key, out var window))
            {
                if (Windows.Count >= MaxKeys) return "DEVOPS_BURST_WINDOW_CAPACITY";
                window = Windows.GetOrAdd(key, _ => new SeenWindow());
            }
            lock (window)
            {
                if (at < window.Latest) return "DEVOPS_BURST_OUT_OF_ORDER";
                window.Observations.RemoveAll(x => x.At < at - TimeSpan.FromMinutes(20));
                foreach (var x in window.Observations)
                    if (x.Id == r.Id) return "DEVOPS_BURST_DUPLICATE_PACKET";
                if (window.Observations.Count >= MaxObservations) return "DEVOPS_BURST_WINDOW_CAPACITY";
                window.Observations.Add((r.Id, at));
                window.Latest = at;
            }
            return null;
        }
    }
}
