// SPDX-License-Identifier: MIT
// File: Engine/Rules/Abstractions/RuleEvaluationResult.cs
using System;
using System.Collections.Generic;
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules
{
    public sealed class RuleEvaluationResult
    {
        public string RuleId { get; init; } = string.Empty;
        public bool Evaluated { get; init; }
        public bool Matched { get; init; }
        public bool Suppressed { get; init; }
        public bool Failed { get; init; }
        public bool Skipped { get; init; }
        public string? FailureMessage { get; init; }
        public IReadOnlyList<DetectionEvent> Events { get; init; } = Array.Empty<DetectionEvent>();
        public IReadOnlyList<RuleNoMatchReason> NoMatchReasons { get; init; } = Array.Empty<RuleNoMatchReason>();

        public static RuleEvaluationResult NoMatch(string ruleId)
            => NoMatch(ruleId, RuleNoMatchReasonCategory.InsufficientEvidence, "NO_MATCH", "Rule evaluated but did not produce sufficient evidence.");

        public static RuleEvaluationResult NoMatch(
            string ruleId,
            RuleNoMatchReasonCategory category,
            string code,
            string message,
            IReadOnlyDictionary<string, string>? details = null)
            => new()
            {
                RuleId = ruleId,
                Evaluated = true,
                NoMatchReasons = new[] { RuleNoMatchReason.Create(ruleId, category, code, message, details: details) }
            };

        public static RuleEvaluationResult SkippedDisabled(string ruleId) => new()
        {
            RuleId = ruleId,
            Skipped = true,
            NoMatchReasons = new[]
            {
                RuleNoMatchReason.Create(ruleId, RuleNoMatchReasonCategory.Disabled, "RULE_DISABLED", "Rule is disabled by runtime policy or configuration.")
            }
        };
        public static RuleEvaluationResult SuppressedMatch(string ruleId) => new() { RuleId = ruleId, Evaluated = true, Matched = true, Suppressed = true };
        public static RuleEvaluationResult Match(string ruleId, DetectionEvent evt) => new() { RuleId = ruleId, Evaluated = true, Matched = true, Events = new[] { evt } };
        public static RuleEvaluationResult Match(string ruleId, IReadOnlyList<DetectionEvent> events) => new() { RuleId = ruleId, Evaluated = true, Matched = true, Events = events ?? Array.Empty<DetectionEvent>() };
        public static RuleEvaluationResult FailedRule(string ruleId, Exception ex) => new() { RuleId = ruleId, Evaluated = true, Failed = true, FailureMessage = ex.Message };
        public static RuleEvaluationResult FailedRule(string ruleId, string message) => new() { RuleId = ruleId, Evaluated = true, Failed = true, FailureMessage = message };
    }
}
