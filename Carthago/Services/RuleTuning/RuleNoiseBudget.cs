// SPDX-License-Identifier: MIT
// File: Services/RuleTuning/RuleNoiseBudget.cs
namespace Carthago.Services.RuleTuning
{
    public sealed record RuleNoiseBudget(
        int MaxAlertsPerRulePerHour,
        int MaxAlertsPerHostPerRulePerHour,
        int MaxShadowEventsPerRulePerHour,
        bool BackoffEnabled = true,
        bool AllowCriticalBypass = false);
}
