// SPDX-License-Identifier: MIT
// File: Engine/Rules/Profiles/RuleProfile.cs
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Profiles
{
    public sealed record RuleProfileRuleDefaults(
        RuleMode Mode,
        SeverityLevel? Severity = null,
        int? Threshold = null,
        int? WindowSeconds = null);

    public sealed record RuleProfile(
        string Name,
        string Description,
        IReadOnlyDictionary<string, RuleProfileRuleDefaults> Defaults);
}
