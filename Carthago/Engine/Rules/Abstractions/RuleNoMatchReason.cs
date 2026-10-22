// SPDX-License-Identifier: MIT
// File: Engine/Rules/Abstractions/RuleNoMatchReason.cs
using System;
using System.Collections.Generic;

namespace Carthago.Engine.Rules
{
    public enum RuleNoMatchReasonCategory
    {
        Unknown,
        Disabled,
        SelectorSkipped,
        MissingTelemetry,
        MissingRequiredField,
        NotApplicableProtocol,
        BoundaryMismatch,
        AssetAllowed,
        ApprovedDestination,
        BelowThreshold,
        InsufficientEvidence,
        Cooldown,
        SuppressionPolicy,
        RuntimePrecisionGate,
        Error
    }

    public sealed record RuleNoMatchReason(
        string RuleId,
        RuleNoMatchReasonCategory Category,
        string Code,
        string Message,
        DateTime TimestampUtc,
        IReadOnlyDictionary<string, string> Details)
    {
        public static RuleNoMatchReason Create(
            string ruleId,
            RuleNoMatchReasonCategory category,
            string code,
            string message,
            DateTime? timestampUtc = null,
            IReadOnlyDictionary<string, string>? details = null)
        {
            return new RuleNoMatchReason(
                string.IsNullOrWhiteSpace(ruleId) ? "UNKNOWN" : ruleId.Trim(),
                category,
                string.IsNullOrWhiteSpace(code) ? category.ToString().ToUpperInvariant() : code.Trim(),
                string.IsNullOrWhiteSpace(message) ? category.ToString() : message.Trim(),
                timestampUtc ?? DateTime.UtcNow,
                details ?? EmptyDetails);
        }

        public static readonly IReadOnlyDictionary<string, string> EmptyDetails = new Dictionary<string, string>();
    }
}
