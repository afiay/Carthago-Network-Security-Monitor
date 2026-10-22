// SPDX-License-Identifier: MIT
// File: Engine/Rules/Execution/RuleExecutionPlan.cs
using System.Collections.Generic;

namespace Carthago.Engine.Rules.Execution
{
    public sealed record RuleExecutionPlanEntry(
        IDetectionRule Rule,
        bool ShouldEvaluate,
        string Reason);

    public sealed record RuleExecutionPlan(
        IReadOnlyList<RuleExecutionPlanEntry> Entries,
        int ConsideredCount,
        int SelectedCount);
}
