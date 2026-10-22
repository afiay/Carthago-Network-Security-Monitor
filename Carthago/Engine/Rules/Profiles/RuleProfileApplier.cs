// SPDX-License-Identifier: MIT
// File: Engine/Rules/Profiles/RuleProfileApplier.cs
using System;

namespace Carthago.Engine.Rules.Profiles
{
    public static class RuleProfileApplier
    {
        public static RuleMode ResolveMode(string? profileName, string ruleId, RuleMode fallback)
        {
            var profile = RuleProfileCatalog.Find(profileName);
            if (profile == null) return fallback;
            return profile.Defaults.TryGetValue(ruleId, out var defaults) ? defaults.Mode : fallback;
        }
    }
}
