// SPDX-License-Identifier: MIT
// File: Services/RuleTuning/RuleNoiseBudgetDecision.cs
using System;

namespace Carthago.Services.RuleTuning
{
    public enum RuleNoiseBudgetDisposition
    {
        Allowed,
        Shadowed,
        Suppressed,
        Bypassed,
        WarningOnly
    }

    public sealed record RuleNoiseBudgetDecision(
        RuleNoiseBudgetDisposition Disposition,
        string Reason,
        int ObservedRuleCount,
        int ObservedHostCount,
        DateTime WindowStartUtc,
        string Recommendation,
        bool DiagnosticsWarning = false);
}
