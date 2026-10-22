// SPDX-License-Identifier: MIT
// File: Services/RuleTuning/RuleSuppressionPolicy.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Services.RuleTuning
{
    public enum RuleSuppressionScope
    {
        Global,
        Rule,
        SourceIp,
        DestinationIp,
        SourceOrDestinationIp,
        DestinationHost,
        DestinationPort,
        Protocol,
        ProcessName,
        SourceAssetRole,
        DestinationAssetRole,
        BoundaryModifier
    }

    public enum RuleSuppressionAction
    {
        None,
        Shadow,
        Suppress
    }

    public sealed record RuleSuppressionPolicy(
        string PolicyId,
        string RuleId,
        RuleSuppressionScope Scope,
        string MatchValue,
        RuleSuppressionAction Action,
        string Reason,
        bool Enabled = true,
        DateTime? CreatedUtc = null,
        DateTime? ExpiresUtc = null,
        string? CreatedBy = null,
        string? TicketReference = null)
    {
        public bool IsExpired(DateTime nowUtc)
            => ExpiresUtc.HasValue && ExpiresUtc.Value <= nowUtc;

        public bool AppliesToRule(string ruleId)
            => string.IsNullOrWhiteSpace(RuleId)
               || RuleId == "*"
               || string.Equals(RuleId, ruleId, StringComparison.OrdinalIgnoreCase);
    }

    public sealed record RuleSuppressionDecision(
        string RuleId,
        bool Matched,
        RuleSuppressionAction Action,
        string? PolicyId,
        RuleSuppressionScope? Scope,
        string? MatchValue,
        string Reason,
        DateTime? ExpiresUtc,
        string? CreatedBy,
        string? TicketReference)
    {
        public static RuleSuppressionDecision None(string ruleId)
            => new(ruleId, false, RuleSuppressionAction.None, null, null, null, string.Empty, null, null, null);
    }

    public sealed record RuleSuppressionPolicyStats(
        string RuleId,
        long TotalPolicyMatches,
        long ShadowedByPolicy,
        long SuppressedByPolicy,
        DateTime? LastMatchedUtc,
        string? LastPolicyId,
        string? LastReason,
        int ActivePolicyCount)
    {
        public static RuleSuppressionPolicyStats Empty(string ruleId)
            => new(ruleId, 0, 0, 0, null, null, null, 0);
    }

    public sealed class RuleSuppressionPolicyStore
    {
        private readonly object _gate = new();
        private List<RuleSuppressionPolicy> _policies = new();

        public static RuleSuppressionPolicyStore Current { get; } = new();

        public IReadOnlyList<RuleSuppressionPolicy> GetActivePolicies(DateTime? nowUtc = null)
        {
            var now = nowUtc ?? DateTime.UtcNow;
            lock (_gate)
            {
                return _policies
                    .Where(policy => policy.Enabled && !policy.IsExpired(now))
                    .OrderBy(policy => policy.RuleId, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(policy => policy.Scope.ToString(), StringComparer.OrdinalIgnoreCase)
                    .ThenBy(policy => policy.MatchValue, StringComparer.OrdinalIgnoreCase)
                    .ToArray();
            }
        }

        public IReadOnlyList<RuleSuppressionPolicy> GetPoliciesForRule(string ruleId, DateTime? nowUtc = null)
        {
            if (string.IsNullOrWhiteSpace(ruleId))
                return Array.Empty<RuleSuppressionPolicy>();

            var now = nowUtc ?? DateTime.UtcNow;
            lock (_gate)
            {
                return _policies
                    .Where(policy => policy.Enabled && !policy.IsExpired(now) && policy.AppliesToRule(ruleId))
                    .OrderByDescending(PolicySpecificity)
                    .ThenBy(policy => policy.PolicyId, StringComparer.OrdinalIgnoreCase)
                    .ToArray();
            }
        }

        public RuleSuppressionPolicy AddOrReplace(RuleSuppressionPolicy policy)
        {
            if (policy == null) throw new ArgumentNullException(nameof(policy));
            var normalized = Normalize(policy);
            lock (_gate)
            {
                _policies.RemoveAll(existing => string.Equals(existing.PolicyId, normalized.PolicyId, StringComparison.OrdinalIgnoreCase));
                _policies.Add(normalized);
                return normalized;
            }
        }

        public bool Remove(string policyId)
        {
            if (string.IsNullOrWhiteSpace(policyId))
                return false;

            lock (_gate)
            {
                return _policies.RemoveAll(policy => string.Equals(policy.PolicyId, policyId.Trim(), StringComparison.OrdinalIgnoreCase)) > 0;
            }
        }

        public void ReplaceAll(IEnumerable<RuleSuppressionPolicy> policies)
        {
            if (policies == null) throw new ArgumentNullException(nameof(policies));
            lock (_gate)
            {
                _policies = policies.Select(Normalize).ToList();
            }
        }

        public void Clear()
        {
            lock (_gate)
            {
                _policies.Clear();
            }
        }

        private static RuleSuppressionPolicy Normalize(RuleSuppressionPolicy policy)
        {
            var id = string.IsNullOrWhiteSpace(policy.PolicyId) ? Guid.NewGuid().ToString("N") : policy.PolicyId.Trim();
            var ruleId = string.IsNullOrWhiteSpace(policy.RuleId) ? "*" : policy.RuleId.Trim();
            var match = policy.MatchValue?.Trim() ?? string.Empty;
            var reason = string.IsNullOrWhiteSpace(policy.Reason) ? "Explicit suppression policy matched." : policy.Reason.Trim();
            var created = policy.CreatedUtc.HasValue
                ? NormalizeUtc(policy.CreatedUtc.Value)
                : DateTime.UtcNow;
            var expires = policy.ExpiresUtc.HasValue ? NormalizeUtc(policy.ExpiresUtc.Value) : (DateTime?)null;
            return policy with
            {
                PolicyId = id,
                RuleId = ruleId,
                MatchValue = match,
                Reason = reason,
                CreatedUtc = created,
                ExpiresUtc = expires,
                CreatedBy = string.IsNullOrWhiteSpace(policy.CreatedBy) ? null : policy.CreatedBy.Trim(),
                TicketReference = string.IsNullOrWhiteSpace(policy.TicketReference) ? null : policy.TicketReference.Trim()
            };
        }

        private static DateTime NormalizeUtc(DateTime value)
            => value.Kind == DateTimeKind.Utc ? value : value.ToUniversalTime();

        internal static int PolicySpecificity(RuleSuppressionPolicy policy)
        {
            var score = 0;
            if (!string.IsNullOrWhiteSpace(policy.RuleId) && policy.RuleId != "*") score += 100;
            score += policy.Scope switch
            {
                RuleSuppressionScope.Global => 0,
                RuleSuppressionScope.Rule => 25,
                RuleSuppressionScope.Protocol => 35,
                RuleSuppressionScope.DestinationPort => 45,
                RuleSuppressionScope.BoundaryModifier => 50,
                RuleSuppressionScope.SourceAssetRole => 60,
                RuleSuppressionScope.DestinationAssetRole => 60,
                RuleSuppressionScope.ProcessName => 70,
                RuleSuppressionScope.DestinationHost => 75,
                RuleSuppressionScope.SourceIp => 80,
                RuleSuppressionScope.DestinationIp => 80,
                RuleSuppressionScope.SourceOrDestinationIp => 80,
                _ => 10
            };
            if (policy.Action == RuleSuppressionAction.Suppress) score += 10;
            return score;
        }
    }

    public sealed class RuleSuppressionPolicyEvaluator
    {
        private readonly RuleSuppressionPolicyStore _store;

        public RuleSuppressionPolicyEvaluator(RuleSuppressionPolicyStore? store = null)
            => _store = store ?? RuleSuppressionPolicyStore.Current;

        public RuleSuppressionDecision Evaluate(DetectionEvent evt, TrafficRecord record, RuleDescriptor descriptor, DateTime? nowUtc = null)
        {
            if (evt == null) throw new ArgumentNullException(nameof(evt));
            if (record == null) throw new ArgumentNullException(nameof(record));
            if (descriptor == null) throw new ArgumentNullException(nameof(descriptor));

            var now = nowUtc ?? DateTime.UtcNow;
            var ruleId = string.IsNullOrWhiteSpace(evt.RuleId) ? descriptor.RuleId : evt.RuleId;
            var assessment = EnvironmentAssessmentService.Current.Assess(record);
            var policies = _store.GetPoliciesForRule(ruleId, now)
                .OrderByDescending(RuleSuppressionPolicyStore.PolicySpecificity)
                .ToArray();

            foreach (var policy in policies)
            {
                if (!policy.AppliesToRule(ruleId))
                    continue;
                if (policy.Action == RuleSuppressionAction.None)
                    continue;
                if (!Matches(policy, evt, record, assessment))
                    continue;

                return new RuleSuppressionDecision(
                    ruleId,
                    Matched: true,
                    policy.Action,
                    policy.PolicyId,
                    policy.Scope,
                    policy.MatchValue,
                    policy.Reason,
                    policy.ExpiresUtc,
                    policy.CreatedBy,
                    policy.TicketReference);
            }

            return RuleSuppressionDecision.None(ruleId);
        }

        private static bool Matches(RuleSuppressionPolicy policy, DetectionEvent evt, TrafficRecord record, EnvironmentAssessment assessment)
        {
            return policy.Scope switch
            {
                RuleSuppressionScope.Global => true,
                RuleSuppressionScope.Rule => true,
                RuleSuppressionScope.SourceIp => ValueMatches(policy.MatchValue, evt.SourceIp, record.Source),
                RuleSuppressionScope.DestinationIp => ValueMatches(policy.MatchValue, evt.DestinationIp, record.Destination),
                RuleSuppressionScope.SourceOrDestinationIp => ValueMatches(policy.MatchValue, evt.SourceIp, record.Source) || ValueMatches(policy.MatchValue, evt.DestinationIp, record.Destination),
                RuleSuppressionScope.DestinationHost => ValueMatches(policy.MatchValue, evt.DestinationHost, record.HttpHost, record.Sni, record.TlsSni, record.DnsQname),
                RuleSuppressionScope.DestinationPort => PortMatches(policy.MatchValue, evt.DestinationPort, record.DestinationPort),
                RuleSuppressionScope.Protocol => ValueMatches(policy.MatchValue, evt.Protocol, record.Protocol, record.ApplicationProtocol, record.ApplicationService),
                RuleSuppressionScope.ProcessName => ValueMatches(policy.MatchValue, evt.ProcessName, record.ProcessName),
                RuleSuppressionScope.SourceAssetRole => RoleMatches(policy.MatchValue, assessment.SourceAsset.Role),
                RuleSuppressionScope.DestinationAssetRole => RoleMatches(policy.MatchValue, assessment.DestinationAsset.Role),
                RuleSuppressionScope.BoundaryModifier => assessment.RiskModifiers.Any(modifier => ValueMatches(policy.MatchValue, modifier)),
                _ => false
            };
        }

        private static bool RoleMatches(string pattern, AssetRole role)
            => ValueMatches(pattern, role.ToString());

        private static bool PortMatches(string pattern, params int?[] values)
        {
            foreach (var value in values)
            {
                if (!value.HasValue)
                    continue;
                if (ValueMatches(pattern, value.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)))
                    return true;
            }
            return false;
        }

        private static bool ValueMatches(string pattern, params string?[] values)
        {
            if (string.IsNullOrWhiteSpace(pattern))
                return false;

            var normalizedPattern = pattern.Trim();
            foreach (var value in values)
            {
                if (string.IsNullOrWhiteSpace(value))
                    continue;

                var candidate = value.Trim();
                if (normalizedPattern == "*")
                    return true;
                if (string.Equals(candidate, normalizedPattern, StringComparison.OrdinalIgnoreCase))
                    return true;
                if (WildcardMatches(candidate, normalizedPattern))
                    return true;
                if (IpOrCidrMatches(candidate, normalizedPattern))
                    return true;
            }

            return false;
        }

        private static bool WildcardMatches(string candidate, string pattern)
        {
            if (!pattern.Contains('*'))
                return false;

            if (pattern.StartsWith("*.", StringComparison.Ordinal) && candidate.EndsWith(pattern[1..], StringComparison.OrdinalIgnoreCase))
                return true;
            if (pattern.EndsWith("*", StringComparison.Ordinal) && candidate.StartsWith(pattern[..^1], StringComparison.OrdinalIgnoreCase))
                return true;
            if (pattern.StartsWith("*", StringComparison.Ordinal) && candidate.EndsWith(pattern[1..], StringComparison.OrdinalIgnoreCase))
                return true;

            var parts = pattern.Split('*', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var offset = 0;
            foreach (var part in parts)
            {
                var found = candidate.IndexOf(part, offset, StringComparison.OrdinalIgnoreCase);
                if (found < 0)
                    return false;
                offset = found + part.Length;
            }

            return true;
        }

        private static bool IpOrCidrMatches(string candidate, string pattern)
        {
            if (!pattern.Contains('/'))
                return false;
            if (!IPAddress.TryParse(candidate, out var address))
                return false;

            var parts = pattern.Split('/', 2, StringSplitOptions.TrimEntries);
            if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var network) || !int.TryParse(parts[1], out var prefix))
                return false;
            var addressBytes = address.GetAddressBytes();
            var networkBytes = network.GetAddressBytes();
            if (addressBytes.Length != networkBytes.Length)
                return false;

            var bitLength = addressBytes.Length * 8;
            if (prefix < 0 || prefix > bitLength)
                return false;

            var fullBytes = prefix / 8;
            var remainingBits = prefix % 8;
            for (var i = 0; i < fullBytes; i++)
            {
                if (addressBytes[i] != networkBytes[i])
                    return false;
            }

            if (remainingBits == 0)
                return true;

            var mask = (byte)(0xFF << (8 - remainingBits));
            return (addressBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
        }
    }

    internal sealed class RuleSuppressionPolicyStatsState
    {
        public long TotalPolicyMatches;
        public long ShadowedByPolicy;
        public long SuppressedByPolicy;
        public DateTime? LastMatchedUtc;
        public string? LastPolicyId;
        public string? LastReason;
    }

    public static class RuleSuppressionAuditStore
    {
        private static readonly object Gate = new();
        private static readonly Dictionary<string, RuleSuppressionPolicyStatsState> States = new(StringComparer.OrdinalIgnoreCase);

        public static void Record(RuleSuppressionDecision decision, DateTime timestampUtc)
        {
            if (decision == null || !decision.Matched || string.IsNullOrWhiteSpace(decision.RuleId))
                return;

            lock (Gate)
            {
                if (!States.TryGetValue(decision.RuleId, out var state))
                {
                    state = new RuleSuppressionPolicyStatsState();
                    States[decision.RuleId] = state;
                }

                state.TotalPolicyMatches++;
                if (decision.Action == RuleSuppressionAction.Shadow)
                    state.ShadowedByPolicy++;
                if (decision.Action == RuleSuppressionAction.Suppress)
                    state.SuppressedByPolicy++;
                state.LastMatchedUtc = timestampUtc.Kind == DateTimeKind.Utc ? timestampUtc : timestampUtc.ToUniversalTime();
                state.LastPolicyId = decision.PolicyId;
                state.LastReason = decision.Reason;
            }
        }

        public static RuleSuppressionPolicyStats Snapshot(string ruleId)
        {
            if (string.IsNullOrWhiteSpace(ruleId))
                return RuleSuppressionPolicyStats.Empty(string.Empty);

            var id = ruleId.Trim();
            lock (Gate)
            {
                var activePolicyCount = RuleSuppressionPolicyStore.Current.GetPoliciesForRule(id).Count;
                if (!States.TryGetValue(id, out var state))
                    return RuleSuppressionPolicyStats.Empty(id) with { ActivePolicyCount = activePolicyCount };

                return new RuleSuppressionPolicyStats(
                    id,
                    state.TotalPolicyMatches,
                    state.ShadowedByPolicy,
                    state.SuppressedByPolicy,
                    state.LastMatchedUtc,
                    state.LastPolicyId,
                    state.LastReason,
                    activePolicyCount);
            }
        }

        public static IReadOnlyList<RuleSuppressionPolicyStats> SnapshotAll()
        {
            lock (Gate)
            {
                return States.Keys
                    .OrderBy(static id => id, StringComparer.OrdinalIgnoreCase)
                    .Select(Snapshot)
                    .ToArray();
            }
        }

        public static void Reset()
        {
            lock (Gate)
            {
                States.Clear();
            }
        }
    }
}
