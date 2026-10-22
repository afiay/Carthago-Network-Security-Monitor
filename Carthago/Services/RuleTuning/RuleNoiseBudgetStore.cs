// SPDX-License-Identifier: MIT
// File: Services/RuleTuning/RuleNoiseBudgetStore.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules.Tuning;

namespace Carthago.Services.RuleTuning
{
    public sealed class RuleNoiseBudgetStore
    {
        private readonly IReadOnlyDictionary<string, RuleNoiseBudget> _overrides;

        public RuleNoiseBudgetStore(IReadOnlyDictionary<string, RuleNoiseBudget>? overrides = null)
            => _overrides = overrides ?? new Dictionary<string, RuleNoiseBudget>(StringComparer.OrdinalIgnoreCase);

        public RuleNoiseBudget GetBudget(string ruleId, string category, RuleTuningTier tier)
        {
            if (_overrides.TryGetValue(ruleId, out var overridden))
                return overridden;

            if (category.Contains("health", StringComparison.OrdinalIgnoreCase))
                return new RuleNoiseBudget(MaxAlertsPerRulePerHour: 6, MaxAlertsPerHostPerRulePerHour: 2, MaxShadowEventsPerRulePerHour: 24, BackoffEnabled: true, AllowCriticalBypass: true);

            if (category.Contains("OT", StringComparison.OrdinalIgnoreCase) || category.Contains("IoT", StringComparison.OrdinalIgnoreCase))
                return tier switch
                {
                    RuleTuningTier.HighFidelityAlert => new RuleNoiseBudget(20, 6, 120, BackoffEnabled: true, AllowCriticalBypass: true),
                    _ => new RuleNoiseBudget(8, 3, 80, BackoffEnabled: true, AllowCriticalBypass: false)
                };

            return tier switch
            {
                RuleTuningTier.HighFidelityAlert => new RuleNoiseBudget(40, 10, 160, BackoffEnabled: true, AllowCriticalBypass: true),
                RuleTuningTier.MediumFidelityAlert => new RuleNoiseBudget(20, 5, 120, BackoffEnabled: true, AllowCriticalBypass: false),
                RuleTuningTier.ShadowFirst => new RuleNoiseBudget(1, 1, 200, BackoffEnabled: true, AllowCriticalBypass: false),
                RuleTuningTier.BaselineRequired => new RuleNoiseBudget(4, 2, 180, BackoffEnabled: true, AllowCriticalBypass: false),
                RuleTuningTier.EnvironmentSpecific => new RuleNoiseBudget(6, 2, 120, BackoffEnabled: true, AllowCriticalBypass: false),
                RuleTuningTier.DisabledUntilConfigured => new RuleNoiseBudget(0, 0, 60, BackoffEnabled: true, AllowCriticalBypass: false),
                RuleTuningTier.HealthOnly => new RuleNoiseBudget(6, 2, 24, BackoffEnabled: true, AllowCriticalBypass: true),
                _ => new RuleNoiseBudget(10, 3, 100)
            };
        }
    }
}
