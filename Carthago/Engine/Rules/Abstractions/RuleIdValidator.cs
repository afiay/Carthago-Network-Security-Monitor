// SPDX-License-Identifier: MIT
// File: Engine/Rules/Abstractions/RuleIdValidator.cs
using System;
using System.Text.RegularExpressions;

namespace Carthago.Engine.Rules
{
    public static class RuleIdValidator
    {
        private static readonly Regex CoreRuleId = new(@"^R(?:00[1-9]|0[1-9][0-9]|[1-9][0-9]{2,})$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex PackRuleId = new(@"^(?!R[0-9]+$)[A-Z][A-Z0-9]{1,9}[0-9]{3}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

        public static bool IsValid(string? ruleId)
            => IsCoreRuleId(ruleId) || IsPackRuleId(ruleId);

        public static bool IsCoreRuleId(string? ruleId)
            {
            if (string.IsNullOrWhiteSpace(ruleId)) return false;
            string value = ruleId.Trim();
            return CoreRuleId.IsMatch(value) && int.TryParse(value.AsSpan(1),
                System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var number) && number > 0;
        }

        internal static int CoreOrder(string ruleId)
            => IsCoreRuleId(ruleId) && int.TryParse(ruleId.Trim().AsSpan(1),
                System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var number)
                ? number : int.MaxValue;

        internal static string SortGroup(string ruleId) => IsCoreRuleId(ruleId) ? "R" : ruleId;

        public static bool IsPackRuleId(string? ruleId)
            => !string.IsNullOrWhiteSpace(ruleId) && PackRuleId.IsMatch(ruleId.Trim());

        public static string Normalize(string ruleId)
            => (ruleId ?? string.Empty).Trim().ToUpperInvariant();
    }
}
