// SPDX-License-Identifier: MIT
// File: Engine/Rules/Abstractions/RuleEvaluationTrace.cs
using System;
using System.Collections.Generic;

namespace Carthago.Engine.Rules
{
    public sealed class RuleEvaluationTrace
    {
        public string? PacketId { get; init; }
        public string? FlowId { get; init; }
        public DateTime TimestampUtc { get; init; }
        public int RulesConsideredCount { get; set; }
        public int RulesSelectedCount { get; set; }
        public List<string> SelectedRuleIds { get; } = new();
        public List<string> SelectorSkippedRuleIds { get; } = new();
        public Dictionary<string, string> SelectorReasonsByRuleId { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> EvaluatedRuleIds { get; } = new();
        public List<string> MatchedRuleIds { get; } = new();
        public List<string> SuppressedRuleIds { get; } = new();
        public List<string> ShadowedRuleIds { get; } = new();
        public List<string> EmittedRuleIds { get; } = new();
        public List<string> FailedRuleIds { get; } = new();
        public List<string> SkippedRuleIds { get; } = new();
        public List<string> PersistedEventIds { get; } = new();
        public List<string> FailedToPersistEventIds { get; } = new();
        public List<string> ExportedEventIds { get; } = new();
        public List<string> GroupedEventIds { get; } = new();
        public List<string> TelemetryWarnings { get; } = new();
        public Dictionary<string, List<string>> MissingTelemetryByRuleId { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, List<RuleNoMatchReason>> NoMatchReasonsByRuleId { get; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
