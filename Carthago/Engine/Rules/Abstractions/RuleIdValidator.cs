// SPDX-License-Identifier: MIT
// File: Engine/Rules/Abstractions/RuleIdValidator.cs
using System;
using System.Text.RegularExpressions;

namespace Carthago.Engine.Rules
{
    public static class RuleIdValidator
    {
        private static readonly Regex CoreRuleId = new(@"^R\d{3}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex PackRuleId = new(@"^(?!R\d{3}$)[A-Z][A-Z0-9]{1,9}\d{3}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

        public static bool IsValid(string? ruleId)
            => IsCoreRuleId(ruleId) || IsPackRuleId(ruleId);

        public static bool IsCoreRuleId(string? ruleId)
            => !string.IsNullOrWhiteSpace(ruleId) && CoreRuleId.IsMatch(ruleId.Trim());

        public static bool IsPackRuleId(string? ruleId)
            => !string.IsNullOrWhiteSpace(ruleId) && PackRuleId.IsMatch(ruleId.Trim());

        public static string Normalize(string ruleId)
            => (ruleId ?? string.Empty).Trim().ToUpperInvariant();
    }
}
