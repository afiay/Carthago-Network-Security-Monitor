// SPDX-License-Identifier: MIT
// File: Engine/Rules/Profiles/RuleProfileCatalog.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Tuning;

namespace Carthago.Engine.Rules.Profiles
{
    public static class RuleProfileCatalog
    {
        public static IReadOnlyList<RuleProfile> All { get; } = RuleTuningCatalog.Profiles
            .Select(Build)
            .ToArray();

        public static RuleProfile? Find(string? name)
            => All.FirstOrDefault(profile => string.Equals(profile.Name, name, StringComparison.OrdinalIgnoreCase));

        private static RuleProfile Build(RuleTuningProfile tuningProfile)
        {
            var defaults = new Dictionary<string, RuleProfileRuleDefaults>(StringComparer.OrdinalIgnoreCase);
            foreach (var descriptor in RuleCatalog.All)
            {
                var decision = RuleTuningCatalog.Resolve(tuningProfile.Name, descriptor);
                defaults[descriptor.RuleId] = new RuleProfileRuleDefaults(decision.DefaultMode, descriptor.DefaultSeverity);
            }

            return new RuleProfile(tuningProfile.Name, tuningProfile.Description, defaults);
        }
    }
}
