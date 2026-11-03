// SPDX-License-Identifier: MIT
// R275 explicit promotion policy.
// SOURCE CANDIDATE — UNVERIFIED. Default-deny and non-ambient.
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;

namespace Carthago.Services.TrustedAudit
{
    /// <summary>
    /// Operator-supplied promotion prerequisites. Merely constructing this
    /// object does not grant trusted evidence and cannot be attached through
    /// the public RuleEvaluationContext API.
    /// </summary>
    public sealed class OAuthDeviceFlowPromotionPolicyOptions
    {
        public bool Enabled { get; init; }
        public IReadOnlyCollection<string> ApprovedIssuerIds { get; init; }
            = Array.Empty<string>();
        public IReadOnlyCollection<string> ApprovedIdentityHosts { get; init; }
            = Array.Empty<string>();
    }

    /// <summary>
    /// Opaque promotion authorization bound to one exact verified capability,
    /// packet and timestamp. It has no public constructor or public surface.
    /// </summary>
    internal sealed class OAuthDeviceFlowPromotionAuthorization
    {
        private readonly OAuthDeviceFlowRuleCapability _capability;

        private OAuthDeviceFlowPromotionAuthorization(
            OAuthDeviceFlowRuleCapability capability)
        {
            _capability = capability;
        }

        internal const string PolicyId = "r275-promotion-v1";

        internal static bool TryAuthorize(
            OAuthDeviceFlowPromotionPolicyOptions? options,
            OAuthDeviceFlowRuleCapability? capability,
            TrafficRecord? record,
            DateTime timestampUtc,
            out OAuthDeviceFlowPromotionAuthorization? authorization,
            out string reason)
        {
            authorization = null;
            reason = "R275_PROMOTION_POLICY_DISABLED";

            if (options == null || !options.Enabled)
                return false;

            if (capability == null || record == null
                || timestampUtc.Kind != DateTimeKind.Utc
                || !capability.IsBoundTo(record, timestampUtc))
            {
                reason = "R275_PROMOTION_CAPABILITY_BINDING_INVALID";
                return false;
            }

            var approvedIssuers = NormalizeIssuers(options.ApprovedIssuerIds);
            if (approvedIssuers.Count < 2
                || string.Equals(capability.FirstIssuerId, capability.SecondIssuerId,
                    StringComparison.Ordinal)
                || !approvedIssuers.Contains(capability.FirstIssuerId)
                || !approvedIssuers.Contains(capability.SecondIssuerId))
            {
                reason = "R275_PROMOTION_ISSUER_POLICY_REJECTED";
                return false;
            }

            var approvedHosts = NormalizeHosts(options.ApprovedIdentityHosts);
            if (approvedHosts.Count == 0
                || string.IsNullOrWhiteSpace(capability.IdentityHost)
                || !approvedHosts.Any(host =>
                    string.Equals(capability.IdentityHost, host, StringComparison.Ordinal)
                    || capability.IdentityHost.EndsWith("." + host,
                        StringComparison.Ordinal)))
            {
                reason = "R275_PROMOTION_IDENTITY_HOST_REJECTED";
                return false;
            }

            authorization = new OAuthDeviceFlowPromotionAuthorization(capability);
            reason = "R275_PROMOTION_AUTHORIZATION_READY";
            return true;
        }

        internal bool IsBoundTo(
            OAuthDeviceFlowRuleCapability capability,
            TrafficRecord record,
            DateTime timestampUtc)
            => ReferenceEquals(_capability, capability)
                && capability.IsBoundTo(record, timestampUtc);

        private static HashSet<string> NormalizeIssuers(
            IReadOnlyCollection<string>? issuers)
        {
            var result = new HashSet<string>(StringComparer.Ordinal);
            if (issuers == null)
                return result;

            foreach (var issuer in issuers)
            {
                if (issuer is not { Length: >= 3 and <= 64 }
                    || !issuer.All(c => char.IsAsciiLetterOrDigit(c)
                        || c is '-' or '_' or '.'))
                    continue;
                result.Add(issuer);
            }
            return result;
        }

        private static HashSet<string> NormalizeHosts(
            IReadOnlyCollection<string>? hosts)
        {
            var result = new HashSet<string>(StringComparer.Ordinal);
            if (hosts == null)
                return result;

            foreach (var host in hosts)
            {
                var normalized = NormalizeHost(host);
                if (normalized.Length > 0)
                    result.Add(normalized);
            }
            return result;
        }

        private static string NormalizeHost(string? host)
        {
            if (string.IsNullOrWhiteSpace(host))
                return string.Empty;
            var normalized = host.Trim().TrimEnd('.').ToLowerInvariant();
            if (normalized.Length is < 1 or > 253
                || normalized.StartsWith(".", StringComparison.Ordinal)
                || normalized.EndsWith(".", StringComparison.Ordinal)
                || normalized.Contains("..", StringComparison.Ordinal)
                || normalized.Any(c => !(char.IsAsciiLetterOrDigit(c)
                    || c is '-' or '.')))
                return string.Empty;
            return normalized;
        }
    }
}
